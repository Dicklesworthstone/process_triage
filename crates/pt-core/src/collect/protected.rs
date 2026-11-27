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
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use tracing::{debug, trace};

use super::types::{ProcessRecord, ScanResult};

#[derive(Default)]
pub(crate) struct PlanningGroupNames {
    records: std::sync::Mutex<HashMap<u32, GroupNameRecord>>,
}

struct GroupNameRecord {
    observed: std::time::Instant,
    name: Result<String, String>,
}

impl PlanningGroupNames {
    /// Cache directory answers (including outages) for one planning burst.
    /// Never cache which GID belongs to a PID. Apply bypasses this cache.
    pub(crate) fn lookup(
        &self,
        gid: u32,
        resolve: impl FnOnce(u32) -> Result<String, String>,
    ) -> Result<String, String> {
        let records = || self.records.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(hit) = records().get(&gid) {
            if hit.observed.elapsed() < std::time::Duration::from_secs(30) {
                return hit.name.clone();
            }
        }
        let name = resolve(gid);
        let mut records = records();
        if records.len() >= 1024 {
            records.clear();
        }
        records.insert(
            gid,
            GroupNameRecord {
                observed: std::time::Instant::now(),
                name: name.clone(),
            },
        );
        name
    }
}

/// Read the process's effective credential group, the meaning of ps "group".
/// Neither its job-control PGID nor its login user's default group identifies it.
#[cfg(target_os = "linux")]
fn effective_gid(pid: u32) -> Result<u32, String> {
    let status = std::fs::read(format!("/proc/{pid}/status"))
        .map_err(|error| format!("cannot read effective GID for PID {pid}: {error}"))?;
    effective_gid_from_status(&status)
        .ok_or_else(|| format!("missing or malformed effective GID for PID {pid}"))
}

#[cfg(any(target_os = "linux", test))]
fn effective_gid_from_status(status: &[u8]) -> Option<u32> {
    let mut rows = status
        .split(|b| *b == b'\n')
        .filter_map(|row| row.strip_prefix(b"Gid:"));
    let parse = |row: &[u8]| {
        let fields: Vec<u32> = std::str::from_utf8(row)
            .ok()?
            .split_ascii_whitespace()
            .map(str::parse)
            .collect::<Result<_, _>>()
            .ok()?;
        let [_, effective, _, _] = fields.as_slice() else {
            return None;
        };
        Some(*effective)
    };
    rows.next()
        .and_then(parse)
        .filter(|_| rows.next().is_none())
}

/// Resolve through the host account directory without permitting an NSS/LDAP
/// outage to hang triage. The account name must be from a record for this GID.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn group_name(gid: u32) -> Result<String, String> {
    let id = gid.to_string();
    #[cfg(target_os = "linux")]
    let (cmd, args): (&str, &[&str]) = ("/usr/bin/getent", &["group", &id]);
    #[cfg(target_os = "macos")]
    let (cmd, args): (&str, &[&str]) = ("/usr/bin/dscacheutil", &["-q", "group", "-a", "gid", &id]);
    let runner = super::tool_runner::ToolRunner::new(super::tool_runner::ToolConfig {
        use_nice: false,
        default_timeout: std::time::Duration::from_secs(2),
        max_output_bytes: 64 * 1024,
        ..Default::default()
    });
    let observed = runner.run_tool(cmd, args, None)
    .map_err(|error| format!("group directory lookup for GID {gid}: {error}"))?;
    if !observed.success() || !observed.stderr.is_empty() {
        return Err(format!(
            "group directory lookup for GID {gid} did not complete"
        ));
    }
    let record = std::str::from_utf8(&observed.stdout)
        .map_err(|_| format!("invalid group directory record for GID {gid}"))?;
    #[cfg(target_os = "linux")]
    let name = parse_getent_group(record, gid);
    #[cfg(target_os = "macos")]
    let name = parse_directory_group(record, gid);
    name.filter(|name| {
        !name.is_empty() && name.trim() == *name && !name.chars().any(char::is_control)
    })
    .map(str::to_owned)
    .ok_or_else(|| format!("ambiguous or missing name for effective GID {gid}"))
}

#[cfg(any(target_os = "linux", test))]
fn parse_getent_group(record: &str, gid: u32) -> Option<&str> {
    let row = record.strip_suffix('\n')?;
    if row.contains('\n') {
        return None;
    }
    let mut fields = row.split(':');
    let name = fields.next()?;
    fields.next()?; // password
    let found = fields.next()?.parse::<u32>().ok()?;
    fields.next()?; // member list
    (found == gid && fields.next().is_none()).then_some(name)
}

#[cfg(any(target_os = "macos", test))]
fn parse_directory_group(record: &str, gid: u32) -> Option<&str> {
    let record = record.trim_matches(['\r', '\n']);
    let mut name = None;
    let mut observed_gid = None;
    for row in record.lines() {
        // An internal blank line starts a second directory record. Reject
        // malformed fields too, including an empty duplicate name or GID.
        let (field, value) = row.split_once(':')?;
        if field.is_empty() || field.trim() != field {
            return None;
        }
        match field {
            "name" => {
                let value = value.strip_prefix(' ')?;
                if value.is_empty() || name.replace(value).is_some() {
                    return None;
                }
            }
            "gid" => {
                let value = value.strip_prefix(' ')?.parse::<u32>().ok()?;
                if observed_gid.replace(value).is_some() {
                    return None;
                }
            }
            _ => {}
        }
    }
    name.filter(|_| observed_gid == Some(gid))
}

#[cfg(test)]
mod group_evidence_tests {
    use super::*;

    #[test]
    fn effective_group_uses_only_the_effective_credential_and_requires_one_complete_row() {
        let status = b"Name:\t\xff\nGid:\t10 20 30 40\nGroups:\t1 2 10\n";
        assert_eq!(effective_gid_from_status(status), Some(20));
        for invalid in [
            &b"Groups: 10 20\n"[..],
            b"Gid: 10 xx 30 40\n",
            b"Gid: 10 20\n",
            b"Gid: 10 20 30 40\nGid: 1 2 3 4\n",
        ] {
            assert_eq!(effective_gid_from_status(invalid), None);
        }
    }

    #[test]
    fn directory_answers_require_one_record_for_the_observed_gid() {
        assert_eq!(
            parse_getent_group("operators_long_name:x:20:user1,user2\n", 20),
            Some("operators_long_name")
        );
        assert_eq!(parse_getent_group("operators:x:21:\n", 20), None);
        assert_eq!(parse_getent_group("one:x:20:\ntwo:x:20:\n", 20), None);
        assert_eq!(
            parse_directory_group("name: staff\npassword: *\ngid: 20\n", 20),
            Some("staff")
        );
        assert_eq!(parse_directory_group("name: staff\ngid: 21\n", 20), None);
        assert_eq!(parse_directory_group("name: staff\n\ngid: 20\n", 20), None);
        assert_eq!(parse_directory_group("name: staff\ngid: 20\nname:\n", 20), None);
        assert_eq!(parse_directory_group("name: staff\ngid: 20\ngid:bad\n", 20), None);
        assert_eq!(
            parse_directory_group("name: staff\ngid: 20\nname: alt\n", 20),
            None
        );
    }

    #[test]
    fn planning_group_names_share_account_lookups_by_gid_only() {
        let names = PlanningGroupNames::default();
        assert_eq!(names.lookup(10, |_| Ok("one".into())).unwrap(), "one");
        assert_eq!(
            names.lookup(10, |_| panic!("already observed")).unwrap(),
            "one"
        );
        assert!(names
            .lookup(20, |_| Err("directory unavailable".into()))
            .is_err());
        assert!(names
            .lookup(20, |_| panic!("do not repeatedly wait on an outage"))
            .is_err());
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn observe_effective_group(
    target: &pt_common::ProcessIdentity,
    lookup: impl FnOnce(u32) -> Result<String, String>,
) -> Result<String, String> {
    use crate::action::{IdentityProvider, LiveIdentityProvider};
    let identity = LiveIdentityProvider::new();
    let validate = || {
        // Darwin's native credential read binds its own birth and UID. A
        // recorded full identity also has to satisfy the live boot check.
        if target.quality == pt_common::IdentityQuality::Full && target.can_safely_revalidate() {
            if identity
                .revalidate(target)
                .map_err(|error| error.to_string())?
            {
                return Ok(());
            }
        } else if cfg!(target_os = "macos")
            && target.quality == pt_common::IdentityQuality::NoBootId
            && target.can_safely_revalidate()
        {
            return Ok(());
        }
        Err("cannot bind protected-group evidence to the target identity".to_string())
    };
    #[cfg(target_os = "linux")]
    let credential = || effective_gid(target.pid.0);
    #[cfg(target_os = "macos")]
    let credential = || {
        super::macos::effective_gid(target)
            .ok_or_else(|| "effective GID or native process identity unavailable".to_string())
    };
    validate()?;
    let gid = credential()?;
    let name = lookup(gid)?;
    if credential()? != gid {
        return Err("effective GID changed during protected-group inspection".to_string());
    }
    validate()?;
    Ok(name)
}

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
            PatternKind::Literal => {
                if case_insensitive {
                    let re_pattern = format!("(?i){}", regex::escape(pattern));
                    Some(Regex::new(&re_pattern).map_err(|e| {
                        ProtectedFilterError::InvalidPattern {
                            path: path.to_string(),
                            message: e.to_string(),
                        }
                    })?)
                } else {
                    None // Use standard string matching
                }
            }
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
                    self.regex
                        .as_ref()
                        .map(|r| r.is_match(text))
                        .unwrap_or_else(|| {
                            // Fallback just in case regex failed to compile (though it shouldn't)
                            text.to_lowercase().contains(&self.original.to_lowercase())
                        })
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
    /// Matched a built-in live-infrastructure rule (`guardrails.builtin_protection`).
    Builtin,
    /// pt itself or one of its ancestors (the invoker chain).
    InvokerChain,
    /// Supervised by systemd or a container runtime (Linux cgroup placement).
    SupervisedService,
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
    /// Apply built-in live-infrastructure protection and cgroup-role logic.
    builtin: bool,
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
            builtin: false,
        })
    }

    /// Enable/disable built-in live-infrastructure protection (see
    /// `Guardrails::builtin_protection`).
    pub fn with_builtin_protection(mut self, enabled: bool) -> Self {
        self.builtin = enabled;
        self
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

        Ok(Self::new(
            &patterns,
            &guardrails.protected_users,
            &guardrails.never_kill_pid,
            &guardrails.never_kill_ppid,
        )?
        .with_builtin_protection(guardrails.builtin_protection))
    }

    /// Check if a process record is protected.
    ///
    /// Returns `Some(ProtectedMatch)` if protected, `None` if not.
    pub fn is_protected(&self, record: &ProcessRecord) -> Option<ProtectedMatch> {
        let role = if self.builtin {
            super::cgroup::read_cgroup_role(record.pid.0)
        } else {
            super::cgroup::CgroupRole::Unknown
        };
        self.is_protected_with_role(record, role)
    }

    /// `is_protected` with an explicit cgroup role (Linux systemd placement).
    ///
    /// With built-in protection on:
    /// - supervised services (system/user units, containers) are protected;
    /// - login-session / transient-scope workloads are exempt from `never_kill_ppid`
    ///   and `protected_users` (a root build started over SSH, or an orphan reparented
    ///   to PID 1, is a legitimate candidate, not a system service).
    pub fn is_protected_with_role(
        &self,
        record: &ProcessRecord,
        role: super::cgroup::CgroupRole,
    ) -> Option<ProtectedMatch> {
        self.is_protected_with_role_and_restart(record, role, false)
    }

    fn is_protected_with_role_and_restart(
        &self,
        record: &ProcessRecord,
        role: super::cgroup::CgroupRole,
        bound_restart: bool,
    ) -> Option<ProtectedMatch> {
        let pid = record.pid.0;
        let ppid = record.ppid.0;
        let make = |field: MatchedField, pattern: String, notes: Option<String>| ProtectedMatch {
            pid,
            comm: record.comm.clone(),
            cmd_truncated: truncate_cmd(&record.cmd, 80),
            matched_field: field,
            pattern,
            notes,
        };

        let mut session_workload = false;
        if self.builtin {
            if let Some((name, notes)) = builtin_protection_match(&record.comm, &record.cmd) {
                return Some(make(
                    MatchedField::Builtin,
                    name.to_string(),
                    Some(notes.to_string()),
                ));
            }
            match builtin_placement(role, &record.user, &record.comm, &record.cmd) {
                BuiltinPlacement::SupervisedService
                    if bound_restart && role == super::cgroup::CgroupRole::UserService => {}
                BuiltinPlacement::SupervisedService => {
                    return Some(make(
                        MatchedField::SupervisedService,
                        format!("cgroup:{role:?}"),
                        Some(SUPERVISED_SERVICE_NOTES.to_string()),
                    ));
                }
                BuiltinPlacement::MacSystem(notes) => {
                    return Some(make(
                        MatchedField::Builtin,
                        MACOS_SYSTEM_RULE.to_string(),
                        Some(notes.to_string()),
                    ));
                }
                BuiltinPlacement::UserWorkload => session_workload = true,
                BuiltinPlacement::Unplaced => {}
            }
        }

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

        // Check protected PPIDs (orphans inside a login session are candidates, not
        // services, when built-in protection classifies them via cgroups)
        if self.protected_ppids.contains(&ppid) && !session_workload {
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

        // Check protected users. Only the `root` entry is relaxed for login-session
        // workloads (it stands in for "system services", and a remote build on a
        // root-run worker is a candidate); users the operator listed explicitly are
        // always honored.
        if self.protected_users.contains(&record.user.to_lowercase())
            && !(session_workload && is_root_user(&record.user))
        {
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
        self.filter_scan_result_with_restarts(scan_result, |_| None)
    }

    /// Admit a user service to planning only with its separately verified
    /// restart binding. This waives placement protection alone: invoker chains,
    /// service ancestors, explicit users/PIDs and command patterns still apply.
    /// The planner must restrict these records to Keep or supervisor Restart.
    pub fn filter_scan_result_with_restarts<'a>(
        &self,
        scan_result: &ScanResult,
        restart: impl FnMut(&ProcessRecord) -> Option<&'a crate::action::SystemdUserServiceBinding>,
    ) -> FilterResult {
        let invoker_chain = if self.builtin {
            invoker_chain_pids(&scan_result.processes)
        } else {
            HashSet::new()
        };
        self.filter_with_observations(
            &scan_result.processes,
            &invoker_chain,
            |record| super::cgroup::read_cgroup_role(record.pid.0),
            restart,
        )
    }

    /// Apply the same filter to explicitly supplied observations. The role
    /// callback and invoker chain may come from a recorded census; this method
    /// does not read cgroups or discover the current process's ancestors.
    ///
    /// Recorded scoring must pass no restart bindings: admitting a service for
    /// execution still requires the live, same-user capability check.
    pub fn filter_with_observations<'a>(
        &self,
        processes: &[ProcessRecord],
        invoker_chain: &HashSet<u32>,
        mut role_for: impl FnMut(&ProcessRecord) -> super::cgroup::CgroupRole,
        mut restart: impl FnMut(&ProcessRecord) -> Option<&'a crate::action::SystemdUserServiceBinding>,
    ) -> FilterResult {
        let total_before = processes.len();
        let mut passed = Vec::with_capacity(total_before);
        let mut filtered = Vec::new();
        let by_pid: std::collections::HashMap<u32, &ProcessRecord> =
            processes.iter().map(|p| (p.pid.0, p)).collect();
        let mut service_ancestors = ScanAncestors::new(&by_pid, |process| {
            is_service_daemon(&process.comm, &process.cmd)
        });

        for record in processes {
            let protection = if self.builtin && invoker_chain.contains(&record.pid.0) {
                Some(ProtectedMatch {
                    pid: record.pid.0,
                    comm: record.comm.clone(),
                    cmd_truncated: truncate_cmd(&record.cmd, 80),
                    matched_field: MatchedField::InvokerChain,
                    pattern: "builtin.invoker_chain".to_string(),
                    notes: Some("pt itself or one of the processes that invoked it".to_string()),
                })
            } else {
                let bound_restart = restart(record).is_some_and(|binding| {
                    binding.target.pid == record.pid
                        && binding.target.start_id == record.start_id
                        && binding.target.uid == record.uid
                        && binding.target.pgid == record.pgid
                        && binding.target.sid == record.sid
                        && binding.matches_target(&binding.target)
                });
                let role = if self.builtin {
                    role_for(record)
                } else {
                    super::cgroup::CgroupRole::Unknown
                };
                self.is_protected_with_role_and_restart(record, role, bound_restart)
                    .or_else(|| {
                        let daemon = self
                            .builtin
                            .then(|| service_ancestors.nearest(record.pid.0))??;
                        Some(ProtectedMatch {
                            pid: record.pid.0,
                            comm: record.comm.clone(),
                            cmd_truncated: truncate_cmd(&record.cmd, 80),
                            matched_field: MatchedField::Builtin,
                            pattern: "builtin.service_child".to_string(),
                            notes: Some(format!(
                                "worker/plugin of service {} (pid {})",
                                daemon.comm, daemon.pid.0
                            )),
                        })
                    })
            };
            if let Some(match_info) = protection {
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

    /// Whether built-in live-infrastructure protection is enabled.
    pub fn builtin_enabled(&self) -> bool {
        self.builtin
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

/// Which process field a built-in rule inspects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuiltinField {
    /// Process basename (`comm`) or the full command line.
    CommOrCmd,
    /// Only the full command line (the rule depends on arguments).
    Cmd,
}

struct BuiltinRule {
    name: &'static str,
    field: BuiltinField,
    regex: Regex,
    notes: &'static str,
}

fn builtin_rule(
    name: &'static str,
    field: BuiltinField,
    pattern: &str,
    notes: &'static str,
) -> BuiltinRule {
    BuiltinRule {
        name,
        field,
        regex: Regex::new(pattern).expect("built-in protection regex compiles"),
        notes,
    }
}

/// Live infrastructure that pt must never offer to kill (`guardrails.builtin_protection`).
///
/// Every rule here comes from a false positive observed on the 2026-09-24 reality-check
/// fleet scan, where each of these was rated P(abandoned) ≈ 1.0.
static BUILTIN_PROTECTED: std::sync::LazyLock<Vec<BuiltinRule>> = std::sync::LazyLock::new(|| {
    use BuiltinField::*;
    vec![
        builtin_rule(
            "builtin.multiplexer",
            CommOrCmd,
            r"^(\S*/)?((frankenterm|wezterm)-mux-server|tmux|zellij|screen|SCREEN|abduco|dtach)(:|\s|$)",
            "terminal multiplexer: hosts every interactive/agent session on the machine",
        ),
        builtin_rule(
            "builtin.agent_coordination",
            Cmd,
            r"^(\S*/)?am(\s+serve(-http)?(\s|$)|\s*$)|^(\S*/)?(mcp-agent-mail|rchd)(\s|$)|^(\S*/)?ntm\s+internal-monitor(\s|$)",
            "shared agent-mail/compilation service or live agent-session monitor",
        ),
        builtin_rule(
            "builtin.ssh_control_master",
            Cmd,
            // Started with -M / ControlMaster=..., or (ControlMaster set in ssh_config)
            // seen by the title OpenSSH gives the master: `ssh: <ControlPath> [mux]`.
            r"^(\S*/)?ssh\s(.*\s)?(-[1246AaCfGgKkMNnqsTtVvXxYy]*M[1246AaCfGgKkMNnqsTtVvXxYy]*|-oControlMaster=\S+|ControlMaster=(yes|auto|autoask|ask))(\s|$)|^ssh: \S.* \[mux\]\s*$",
            "SSH ControlMaster: shared connection used by rch and other remote tools",
        ),
        builtin_rule(
            "builtin.mux_transport",
            Cmd,
            // Local (`nc -U .../frankenterm/sock`) or over ssh (`ssh host nc -U ...`,
            // `ssh host wezterm cli proxy`), e.g. a GUI terminal's remote domain.
            r"^(\S*/)?(ssh\s.*\s)?(nc|ncat|netcat|socat)\s.*(frankenterm|wezterm|tmux|zellij|screen)|^(\S*/)?ssh\s.*\s(frankenterm|wezterm)\s+cli\s+proxy",
            "terminal multiplexer client transport: carries a live remote session",
        ),
        builtin_rule(
            "builtin.session_infrastructure",
            CommOrCmd,
            r"^(\S*/)?(sshd(-session)?|login|agetty|getty|mingetty|\(sd-pam\)|systemd|dbus-daemon|dbus-broker(-launch)?|pipewire(-pulse)?|wireplumber|pulseaudio|gpg-agent|ssh-agent|gnome-keyring-daemon|at-spi2-registryd|at-spi-bus-launcher|xdg-desktop-portal\S*|xdg-document-portal|xdg-permission-store|launchd|loginwindow|WindowServer)(:|\s|$)",
            "login/desktop session infrastructure",
        ),
        builtin_rule(
            "builtin.display_manager_session",
            CommOrCmd,
            // The process a display manager or session manager keeps alive for the
            // whole graphical login: when it exits, the desktop session ends. They
            // run in the login session's scope (often as root), so neither the
            // service-cgroup nor the root rule covers them (GH #14: sddm-helper
            // was offered for PAUSE). `uwsm start` is the uwsm session launcher.
            r"^(\S*/)?(sddm-helper|sddm-helper-start-wayland|sddm-helper-start-x11user|gdm-session-worker|gdm-wayland-session|gdm-x-session|lightdm|greetd|gnome-session-binary|gnome-session-service|gnome-session-ctl|ksmserver|startplasma-wayland|startplasma-x11|plasma_session|xfce4-session|lxqt-session|lxsession|mate-session|cinnamon-session)(:|\s|$)|(^|/)uwsm(\.py)?\s+start(\s|$)",
            "display-manager / session-manager process that holds the graphical login: killing it ends the desktop session",
        ),
        builtin_rule(
            "builtin.session_host",
            CommOrCmd,
            // Things a person is looking at or that host a session: terminal
            // emulators, display servers/compositors (incl. kiosk `cage`) and live
            // monitors. Headless `Xvfb` is deliberately absent (orphaned Xvfb from
            // test runs are real candidates).
            r"^(\S*/)?(foot|footclient|kitty|alacritty|wezterm-gui|ghostty|gnome-terminal-server|konsole|xfce4-terminal|tilix|terminator|xterm|urxvt|Xorg|Xwayland|cage|sway|Hyprland|weston|labwc|river|niri|gnome-shell|kwin_wayland|kwin_x11|htop|btop|btm|top|atop|glances|nvtop)(:|\s|$)",
            "terminal emulator, display server or live monitor: someone's screen",
        ),
        builtin_rule(
            SERVICE_DAEMON_RULE,
            CommOrCmd,
            // comm keeps the daemon name when the server rewrites its title
            // ("postgres: 18/main: io worker", "nginx: worker process").
            r"^(\S*/)?(postgres|postmaster|mysqld|mariadbd|mongod|mongos|redis-server|redis-sentinel|valkey-server|keydb-server|memcached|nginx|httpd|apache2|caddy|haproxy|traefik|envoy|php-fpm[0-9.]*|clickhouse\S*|influxd|etcd|rabbitmq-server|beam\.smp|mattermost|minio|elasticsearch|opensearch)(:|\s|$)",
            "database / web / message server (and, via parent identity, its workers and plugins)",
        ),
        builtin_rule(
            "builtin.interactive_shell",
            Cmd,
            r"^-?(\S*/)?(ba|z|fi|da|k|tc|c|nu|x)?sh(\s+(-l|--login|-i|--interactive))*$",
            "interactive shell: someone's terminal (shells running `-c <command>` are not covered)",
        ),
    ]
});

const AGENT_CLI_REVIEW_NOTES: &str =
    "AI agent CLI session: may be mid-task; kill only after manual review";

/// Agent CLIs: shown for review, never killed by robot/agent mode, never pre-selected.
static BUILTIN_FORCE_REVIEW: std::sync::LazyLock<Vec<BuiltinRule>> = std::sync::LazyLock::new(
    || {
        vec![builtin_rule(
            "builtin.agent_cli",
            BuiltinField::Cmd,
            // Direct invocation, or an agent in command position inside a shell's -c
            // script (start of the script, or after ; & | ( or a quote), e.g.
            // `zsh -ic '...; cod --no-alt-screen ...'` (`cod` is an installer's codex
            // wrapper). Mentions as arguments (`rg codex src/`) do not count.
            r#"(^|/)(claude|codex|cod|agy|agy-real|gemini|cursor-agent|aider|opencode|goose|amp|crush|qwen|droid)(\s|$)|^(\S*/)?(ba|z|da|fi|k)?sh\s+-[A-Za-z]*c[A-Za-z]*\s+(['"]?|.*[;&|('"]\s*)(claude|codex|cod|agy|gemini|cursor-agent|aider|opencode)(\s|$)|/claude/versions/|/\.?claude-code/|@anthropic-ai/claude-code|@openai/codex|/codex-(linux|darwin)-|@google/gemini-cli"#,
            AGENT_CLI_REVIEW_NOTES,
        )]
    },
);

fn builtin_match(
    rules: &[BuiltinRule],
    comm: &str,
    cmd: &str,
) -> Option<(&'static str, &'static str)> {
    rules.iter().find_map(|rule| {
        let hit = match rule.field {
            BuiltinField::CommOrCmd => rule.regex.is_match(comm) || rule.regex.is_match(cmd),
            BuiltinField::Cmd => rule.regex.is_match(cmd),
        };
        hit.then_some((rule.name, rule.notes))
    })
}

/// Built-in live-infrastructure protection (rule name, notes), if any applies.
pub fn builtin_protection_match(comm: &str, cmd: &str) -> Option<(&'static str, &'static str)> {
    builtin_match(&BUILTIN_PROTECTED, comm, cmd)
}

/// Recognize Pi only in executable/script position. The native fleet binary is
/// named `pi`; the JavaScript package exposes its `dist/cli.js` entrypoint.
/// Package paths mentioned by search tools or unrelated scripts are not agents.
fn pi_agent_command(cmd: &str) -> bool {
    let mut arguments = cmd.split_whitespace();
    let Some(executable) = arguments.next() else {
        return false;
    };
    let executable = executable.rsplit('/').next().unwrap_or(executable);
    if executable == "pi" {
        return true;
    }
    if !matches!(executable, "node" | "nodejs" | "bun") {
        return false;
    }
    let Some(script) = arguments.next() else {
        return false;
    };
    const ENTRYPOINT: &str = "@mariozechner/pi-coding-agent/dist/cli.js";
    script == ENTRYPOINT
        || script
            .strip_suffix(ENTRYPOINT)
            .is_some_and(|prefix| prefix.ends_with('/'))
}

/// Built-in force-review match (agent CLIs), if any applies.
pub fn builtin_force_review_match(cmd: &str) -> Option<(&'static str, &'static str)> {
    // Agent CLIs are identified by their command line; comm is too short/ambiguous.
    if pi_agent_command(cmd) {
        Some(("builtin.agent_cli", AGENT_CLI_REVIEW_NOTES))
    } else {
        builtin_match(&BUILTIN_FORCE_REVIEW, "", cmd)
    }
}

/// Live FUSE servers are infrastructure for every process accessing their mounts.
pub const FUSE_SERVER_RULE: &str = "builtin.fuse_server";

/// Remediation guidance shared by recommendations and execution pre-checks.
pub const FUSE_SERVER_NOTES: &str =
    "holds /dev/fuse: stopping the server can hang every mount accessor, and killing it can strand the mount; review its mounts and unmount with fusermount -u <mountpoint> first";

/// Whether a process holds the Linux FUSE device open.
///
/// Threads can own separate descriptor tables after unshare(CLONE_FILES), so a
/// leader-only inspection cannot establish absence. Negative evidence requires
/// two complete, matching observations of every task identity and descriptor
/// table. All directory entries share one work/deadline budget across both passes.
///
/// Only read procfs descriptor symlinks; following them or stat'ing a mount can
/// itself hang on an unhealthy FUSE server. An observed device is sufficient for
/// a conservative refusal even if other evidence is unavailable or has changed.
/// None means inspection was incomplete, changing, or unsupported. The checks
/// detect observed churn; they do not make a later action atomic.
pub fn holds_fuse_device(pid: u32) -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        holds_fuse_device_from(
            std::path::Path::new(&format!("/proc/{pid}")),
            pid,
            &mut FuseInspectionBudget::default(),
            || {},
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

#[cfg(target_os = "linux")]
struct FuseInspectionBudget {
    deadline: std::time::Instant,
    remaining_entries: usize,
    max_tasks: usize,
}

#[cfg(target_os = "linux")]
impl Default for FuseInspectionBudget {
    fn default() -> Self {
        Self {
            deadline: std::time::Instant::now() + std::time::Duration::from_millis(500),
            remaining_entries: 50_000,
            max_tasks: 1024,
        }
    }
}

#[cfg(target_os = "linux")]
impl FuseInspectionBudget {
    fn available(&self) -> bool {
        std::time::Instant::now() < self.deadline
    }

    fn take_entry(&mut self) -> bool {
        if !self.available() || self.remaining_entries == 0 {
            return false;
        }
        self.remaining_entries -= 1;
        true
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
struct FuseTaskIdentity {
    device: u64,
    inode: u64,
    birth_ticks: u64,
    uid: u32,
}

#[cfg(target_os = "linux")]
type FuseDescriptorTable = std::collections::BTreeMap<u32, std::path::PathBuf>;

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
enum FuseInspection {
    Present,
    Incomplete,
    Clear(std::collections::BTreeMap<u32, (FuseTaskIdentity, FuseDescriptorTable)>),
}

#[cfg(target_os = "linux")]
fn fuse_procfs_id(name: &std::ffi::OsStr, allow_zero: bool) -> Option<u32> {
    let text = name.to_str()?;
    let value = text.parse::<u32>().ok()?;
    (text == value.to_string() && value <= i32::MAX as u32 && (allow_zero || value != 0))
        .then_some(value)
}

#[cfg(target_os = "linux")]
fn fuse_task_ids(
    process_dir: &std::path::Path,
    budget: &mut FuseInspectionBudget,
) -> (std::collections::BTreeSet<u32>, bool) {
    let mut tids = std::collections::BTreeSet::new();
    let Ok(entries) = std::fs::read_dir(process_dir.join("task")) else {
        return (tids, false);
    };
    let mut complete = true;
    for entry in entries {
        if !budget.take_entry() || tids.len() >= budget.max_tasks {
            return (tids, false);
        }
        let tid = entry
            .ok()
            .and_then(|entry| fuse_procfs_id(&entry.file_name(), false));
        match tid {
            Some(tid) if tids.insert(tid) => {}
            _ => complete = false,
        }
    }
    (tids, complete && budget.available())
}

#[cfg(target_os = "linux")]
fn fuse_task_identity(task_dir: &std::path::Path, tid: u32) -> Option<FuseTaskIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(task_dir).ok()?;
    if !metadata.is_dir() {
        return None;
    }
    let bytes = super::procfs::read_bounded(&task_dir.join("stat"), 16 * 1024).ok()?;
    let content = std::str::from_utf8(&bytes).ok()?;
    let stat = super::proc_parsers::parse_required_proc_stat_content(tid, content).ok()?;
    Some(FuseTaskIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        birth_ticks: stat.starttime,
        uid: metadata.uid(),
    })
}

#[cfg(target_os = "linux")]
fn fuse_device_table_snapshot(
    directory: &std::path::Path,
    budget: &mut FuseInspectionBudget,
    descriptors: &mut FuseDescriptorTable,
) -> Option<bool> {
    let entries = std::fs::read_dir(directory).ok()?;
    let mut exhausted = false;
    let targets = entries
        .take_while(|_| {
            let permitted = budget.take_entry();
            exhausted = !permitted;
            permitted
        })
        .map(|entry| {
            let entry = entry?;
            let fd = fuse_procfs_id(&entry.file_name(), true)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            let target = std::fs::read_link(entry.path())?;
            if descriptors.insert(fd, target.clone()).is_some() {
                return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
            }
            Ok(target)
        });
    let result = fuse_device_from_link_targets(targets);
    if result == Some(true) {
        result
    } else if exhausted || !budget.available() {
        None
    } else {
        result
    }
}

#[cfg(target_os = "linux")]
fn fuse_device_snapshot(
    process_dir: &std::path::Path,
    pid: u32,
    budget: &mut FuseInspectionBudget,
) -> FuseInspection {
    let (tids, mut complete) = fuse_task_ids(process_dir, budget);
    complete &= tids.contains(&pid);
    let mut tasks = std::collections::BTreeMap::new();
    for &tid in &tids {
        if !budget.available() {
            return FuseInspection::Incomplete;
        }
        let task_dir = process_dir.join("task").join(tid.to_string());
        let before = fuse_task_identity(&task_dir, tid);
        let mut descriptors = FuseDescriptorTable::new();
        match fuse_device_table_snapshot(&task_dir.join("fd"), budget, &mut descriptors) {
            Some(true) => return FuseInspection::Present,
            Some(false) => {}
            None => complete = false,
        }
        let after = fuse_task_identity(&task_dir, tid);
        complete &= before.is_some() && before == after;
        if let Some(identity) = before {
            tasks.insert(tid, (identity, descriptors));
        }
    }
    let (after_tids, after_complete) = fuse_task_ids(process_dir, budget);
    if complete && after_complete && tids == after_tids && budget.available() {
        FuseInspection::Clear(tasks)
    } else {
        FuseInspection::Incomplete
    }
}

#[cfg(target_os = "linux")]
fn holds_fuse_device_from(
    process_dir: &std::path::Path,
    pid: u32,
    budget: &mut FuseInspectionBudget,
    before_recheck: impl FnOnce(),
) -> Option<bool> {
    if pid == 0 || pid > i32::MAX as u32 || !budget.available() {
        return None;
    }
    let before = match fuse_device_snapshot(process_dir, pid, budget) {
        FuseInspection::Present => return Some(true),
        FuseInspection::Incomplete => return None,
        FuseInspection::Clear(tasks) => tasks,
    };
    before_recheck();
    match fuse_device_snapshot(process_dir, pid, budget) {
        FuseInspection::Present => Some(true),
        FuseInspection::Clear(after) if before == after => Some(false),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn fuse_device_from_link_targets(
    targets: impl IntoIterator<Item = std::io::Result<std::path::PathBuf>>,
) -> Option<bool> {
    let mut complete = true;
    for target in targets {
        match target {
            // Unlinking the device node does not close an existing connection.
            Ok(target)
                if target == std::path::Path::new("/dev/fuse")
                    || target == std::path::Path::new("/dev/fuse (deleted)") =>
            {
                return Some(true);
            }
            Ok(_) => {}
            // A vanished descriptor is incomplete evidence, not proof of absence.
            Err(_) => complete = false,
        }
    }
    complete.then_some(false)
}

/// Best-effort mount attribution for display, never evidence that a server is safe.
///
/// A mount is attributed only when a FUSE entry in the target's mount namespace
/// has a mountpoint exactly present in that process's argv (including an option
/// value). This deliberately omits mounts when a daemon drops its mount argument.
/// No mount path is opened, canonicalized or stat'ed.
pub fn fuse_mountpoints(pid: u32) -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            return Vec::new();
        };
        let Ok(mountinfo) = std::fs::read_to_string(format!("/proc/{pid}/mountinfo")) else {
            return Vec::new();
        };
        fuse_mountpoints_from_inputs(&mountinfo, &cmdline)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
fn fuse_mountpoints_from_inputs(mountinfo: &str, cmdline: &[u8]) -> Vec<String> {
    let arguments: Vec<&[u8]> = cmdline
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .collect();
    let mut mounts = std::collections::BTreeSet::new();
    for line in mountinfo.lines() {
        let Some((mount, filesystem)) = line.split_once(" - ") else {
            continue;
        };
        let Some(kind) = filesystem.split_whitespace().next() else {
            continue;
        };
        if kind != "fuse" && kind != "fuseblk" && !kind.starts_with("fuse.") {
            continue;
        }
        let Some(encoded) = mount.split_whitespace().nth(4) else {
            continue;
        };
        let Some(mountpoint) = decode_mountinfo_path(encoded.as_bytes()) else {
            continue;
        };
        if arguments.iter().any(|argument| {
            *argument == mountpoint.as_slice()
                || (argument.starts_with(b"-")
                    && argument
                        .splitn(2, |byte| *byte == b'=')
                        .nth(1)
                        .is_some_and(|value| value == mountpoint.as_slice()))
        }) {
            mounts.insert(String::from_utf8_lossy(&mountpoint).into_owned());
        }
    }
    mounts.into_iter().collect()
}

#[cfg(target_os = "linux")]
fn decode_mountinfo_path(encoded: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut cursor = 0;
    while cursor < encoded.len() {
        if encoded[cursor] != b'\\' {
            decoded.push(encoded[cursor]);
            cursor += 1;
            continue;
        }
        let escaped = encoded.get(cursor + 1..cursor + 4)?;
        decoded.push(match escaped {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => return None,
        });
        cursor += 4;
    }
    Some(decoded)
}

/// Which AI agent CLI a command line runs (`claude`, `codex`, `gemini`, `cursor`,
/// `aider`, ...), for processes the agent-CLI rule matches; `None` otherwise.
pub fn agent_kind(cmd: &str) -> Option<&'static str> {
    static KIND: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r"\b(claude|codex|cursor-agent|agy|gemini|aider|opencode|goose|amp|crush|qwen|droid)\b|(?:^|[/\s;&|('\x22])(cod)(?:\s|$)",
        )
        .expect("agent kind regex")
    });
    // Pi's prompt/model arguments may mention other agents. Its verified command
    // position takes precedence over the legacy name search through the command.
    if pi_agent_command(cmd) {
        return Some("pi");
    }
    builtin_force_review_match(cmd)?;
    let caps = KIND.captures(cmd)?;
    let name = caps.get(1).or_else(|| caps.get(2))?.as_str();
    Some(match name {
        "claude" => "claude",
        "codex" | "cod" => "codex",
        "agy" | "gemini" => "gemini",
        "cursor-agent" => "cursor",
        "aider" => "aider",
        "opencode" => "opencode",
        "goose" => "goose",
        "amp" => "amp",
        "crush" => "crush",
        "qwen" => "qwen",
        _ => "droid",
    })
}

/// How a transcript was associated with the recognized agent. Neither source
/// identifies the writer of a particular modification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSessionActivitySource {
    HeldWritableDescriptor,
    ExplicitSessionArgument,
}

/// Activity on a transcript associated with the recognized agent.
/// This does not establish abandonment when no transcript was observed.
/// Paths and transcript contents are omitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSessionActivity {
    pub identity: pt_common::ProcessIdentity,
    pub ppid: u32,
    pub command_sha256: String,
    /// Older observations used held writable descriptors exclusively.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<AgentSessionActivitySource>,
    pub identity_verified: bool,
    pub observed_at: chrono::DateTime<chrono::Utc>,
    pub window_seconds: u64,
    pub transcript_count: usize,
    pub latest_modified_at: Option<chrono::DateTime<chrono::Utc>>,
    pub unavailable: Vec<String>,
}

impl AgentSessionActivity {
    fn unavailable(process: &ProcessRecord, window_seconds: u64, reason: &str) -> Self {
        Self {
            identity: pt_common::ProcessIdentity::full(
                process.pid.0,
                process.start_id.clone(),
                process.uid,
                process.pgid,
                process.sid,
                pt_common::IdentityQuality::Full,
            ),
            ppid: process.ppid.0,
            command_sha256: agent_command_digest(&process.cmd),
            source: None,
            identity_verified: false,
            observed_at: chrono::Utc::now(),
            window_seconds,
            transcript_count: 0,
            latest_modified_at: None,
            unavailable: vec![reason.to_string()],
        }
    }

    /// Process replacement, observed command changes, reparenting and job changes
    /// invalidate this observation. Ordinary scheduler-state changes do not.
    pub fn matches_record(&self, process: &ProcessRecord) -> bool {
        self.identity_verified
            && self.identity.quality == pt_common::IdentityQuality::Full
            && self.identity.pid == process.pid
            && self.identity.start_id == process.start_id
            && self.identity.uid == process.uid
            && self.identity.pgid == process.pgid
            && self.identity.sid == process.sid
            && self.ppid == process.ppid.0
            && self.command_sha256 == agent_command_digest(&process.cmd)
            && agent_kind(&process.cmd).is_some()
            && !matches!(
                process.state,
                crate::collect::ProcessState::Zombie
                    | crate::collect::ProcessState::Dead
                    | crate::collect::ProcessState::Unknown
            )
    }

    /// Freshness is evaluated at the recorded observation time. Replay never
    /// consults today's filesystem or clock, and future timestamps are unknown.
    pub fn recently_modified(&self) -> Option<bool> {
        self.recently_modified_within(self.window_seconds)
    }

    pub(crate) fn recently_modified_within(&self, window_seconds: u64) -> Option<bool> {
        if !self.identity_verified || window_seconds == 0 || self.transcript_count == 0 {
            return None;
        }
        let age = (self.observed_at - self.latest_modified_at?)
            .to_std()
            .ok()?;
        let recent = age < std::time::Duration::from_secs(window_seconds);
        // A positive observation survives partial collection. Stale evidence
        // cannot establish quiet when another descriptor/task was unavailable.
        (recent || self.unavailable.is_empty()).then_some(recent)
    }
}

fn agent_command_digest(command: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(command.as_bytes()))
}

/// Collect transcript metadata once for a scan's recognized agent roots.
/// Inspect held writable descriptors, or a native Pi invocation's unambiguous
/// absolute --session argument. Never choose another session's newest file or
/// a path supplied through an environment variable. Missing, unsupported or
/// unreadable transcript evidence remains unknown.
pub fn collect_agent_session_activity(
    processes: &[&ProcessRecord],
    window_seconds: u64,
) -> std::collections::BTreeMap<u32, AgentSessionActivity> {
    #[cfg(target_os = "linux")]
    {
        agent_session::collect(processes, window_seconds)
    }
    #[cfg(not(target_os = "linux"))]
    {
        processes
            .iter()
            .filter(|process| agent_kind(&process.cmd).is_some())
            .map(|process| {
                (
                    process.pid.0,
                    AgentSessionActivity::unavailable(
                        process,
                        window_seconds,
                        if window_seconds == 0 {
                            "session transcript activity lookup is disabled by policy"
                        } else {
                            "session transcript descriptor inspection is unsupported on this platform"
                        },
                    ),
                )
            })
            .collect()
    }
}

/// Probe the test host separately from collection. Known kernel/seccomp refusal
/// still exercises the production Unknown contract; unexpected errors fail.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn cached_session_lookup_available_for_test() -> bool {
    use std::ffi::CString;
    use std::fs::{File, OpenOptions};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let directory = tempfile::tempdir().unwrap();
    File::create(directory.path().join("probe.jsonl")).unwrap();
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(directory.path())
        .unwrap();
    let path = CString::new("probe.jsonl").unwrap();
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: 0x04 | 0x10 | 0x20,
    };
    // SAFETY: the owned root, C string and Linux open_how remain live during
    // this controlled syscall against a file just created by this test.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            path.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if descriptor >= 0 {
        // SAFETY: successful openat2 returned a new owned descriptor.
        drop(unsafe { File::from_raw_fd(descriptor as std::os::fd::RawFd) });
        true
    } else {
        let error = std::io::Error::last_os_error();
        assert!(
            matches!(
                error.raw_os_error(),
                Some(libc::ENOSYS | libc::EINVAL | libc::EPERM)
            ),
            "unexpected failure of the controlled cache-only lookup probe: {error}"
        );
        false
    }
}

#[cfg(target_os = "linux")]
mod agent_session {
    use super::{agent_kind, AgentSessionActivity, AgentSessionActivitySource, ProcessRecord};
    use crate::collect::proc_parsers::parse_required_proc_stat_content;
    use crate::collect::procfs::{directory_path, mount_id, read_bounded, FilesystemGuard};
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::CString;
    use std::fs::{self, File, OpenOptions};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Component, Path, PathBuf};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const MAX_FIELD_BYTES: usize = 65_536;
    const MAX_TASKS: usize = 128;
    const MAX_DESCRIPTORS: usize = 4096;
    const SCAN_BUDGET: Duration = Duration::from_millis(250);
    const PROCESS_BUDGET: Duration = Duration::from_millis(50);

    struct Context {
        boot: String,
        boot_time: SystemTime,
        ticks_per_second: u64,
        filesystems: FilesystemGuard,
        deadline: Instant,
        process_budget: Duration,
    }

    impl Context {
        fn load(deadline: Instant) -> Result<Self, &'static str> {
            let boot = read_bounded(Path::new("/proc/sys/kernel/random/boot_id"), 128)?;
            let boot = std::str::from_utf8(&boot)
                .map_err(|_| "session_boot_identity_unavailable")?
                .trim();
            if uuid::Uuid::parse_str(boot).is_err() {
                return Err("session_boot_identity_unavailable");
            }
            let stat = read_bounded(Path::new("/proc/stat"), 2_097_152)?;
            let stat = std::str::from_utf8(&stat).map_err(|_| "session_boot_time_unavailable")?;
            let mut boot_times = stat.lines().filter_map(|line| line.strip_prefix("btime "));
            let seconds = boot_times
                .next()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|seconds| *seconds > 0)
                .ok_or("session_boot_time_unavailable")?;
            if boot_times.next().is_some() {
                return Err("session_boot_time_unavailable");
            }
            Ok(Self {
                boot: boot.to_string(),
                boot_time: UNIX_EPOCH
                    .checked_add(Duration::from_secs(seconds))
                    .ok_or("session_boot_time_unavailable")?,
                ticks_per_second: crate::collect::tick_delta::clk_tck(),
                filesystems: FilesystemGuard::load()?,
                deadline,
                process_budget: PROCESS_BUDGET,
            })
        }

        fn birth(&self, ticks: u64) -> Result<SystemTime, &'static str> {
            if self.ticks_per_second == 0 {
                return Err("session_process_birth_unavailable");
            }
            let nanos = (ticks % self.ticks_per_second)
                .checked_mul(1_000_000_000)
                .ok_or("session_process_birth_unavailable")?
                / self.ticks_per_second;
            self.boot_time
                .checked_add(Duration::new(ticks / self.ticks_per_second, nanos as u32))
                .ok_or("session_process_birth_unavailable")
        }
    }

    fn check_budget(deadline: Instant) -> Result<(), &'static str> {
        if Instant::now() >= deadline {
            Err("session_observation_budget_exhausted")
        } else {
            Ok(())
        }
    }

    fn pin_directory(path: &Path) -> Result<File, &'static str> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| "session_process_directory_unavailable")
    }

    #[derive(Debug, PartialEq, Eq)]
    struct TaskIdentity {
        device: u64,
        inode: u64,
        birth_ticks: u64,
    }

    fn task_identity(
        task: &File,
        tid: u32,
        process: &ProcessRecord,
    ) -> Result<(TaskIdentity, crate::collect::ProcessStat), &'static str> {
        let metadata = task
            .metadata()
            .map_err(|_| "session_task_identity_unavailable")?;
        let stat = read_bounded(&directory_path(task, "stat"), MAX_FIELD_BYTES)?;
        let stat = std::str::from_utf8(&stat).map_err(|_| "session_task_stat_unavailable")?;
        let stat = parse_required_proc_stat_content(tid, stat)
            .map_err(|_| "session_task_stat_unavailable")?;
        let status = read_bounded(&directory_path(task, "status"), MAX_FIELD_BYTES)?;
        let status = std::str::from_utf8(&status).map_err(|_| "session_task_status_unavailable")?;
        let mut uid_lines = status.lines().filter_map(|line| line.strip_prefix("Uid:"));
        let uids: Vec<_> = uid_lines
            .next()
            .ok_or("session_task_uid_unavailable")?
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<_, _>>()
            .map_err(|_| "session_task_uid_unavailable")?;
        let mut tgid_lines = status.lines().filter_map(|line| line.strip_prefix("Tgid:"));
        let tgid = tgid_lines
            .next()
            .and_then(|value| value.trim().parse::<u32>().ok())
            .ok_or("session_task_group_unavailable")?;
        if uids.len() != 4
            || uids.iter().any(|uid| *uid != process.uid)
            || uid_lines.next().is_some()
            || tgid != process.pid.0
            || tgid_lines.next().is_some()
            || !matches!(
                stat.state,
                'R' | 'S' | 'D' | 'T' | 't' | 'I' | 'P' | 'W' | 'K'
            )
        {
            return Err("session_task_identity_changed_or_unusable");
        }
        Ok((
            TaskIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
                birth_ticks: stat.starttime,
            },
            stat,
        ))
    }

    fn root_identity(
        root: &File,
        process: &ProcessRecord,
        context: &Context,
    ) -> Result<TaskIdentity, &'static str> {
        let (identity, stat) = task_identity(root, process.pid.0, process)?;
        if stat.ppid != process.ppid.0
            || stat.comm != process.comm
            || u32::try_from(stat.pgrp).ok() != process.pgid
            || u32::try_from(stat.session).ok() != process.sid
            || pt_common::StartId::from_linux(&context.boot, stat.starttime, stat.pid)
                != process.start_id
            || matches!(
                process.state,
                crate::collect::ProcessState::Zombie
                    | crate::collect::ProcessState::Dead
                    | crate::collect::ProcessState::Unknown
            )
        {
            return Err("session_process_identity_changed_or_unusable");
        }
        let raw_command = read_bounded(&directory_path(root, "cmdline"), MAX_FIELD_BYTES)?;
        if raw_command.last() != Some(&0) {
            return Err("session_command_unavailable");
        }
        let command = std::str::from_utf8(&raw_command)
            .map_err(|_| "session_command_unavailable")?
            .replace('\0', " ");
        if command.trim() != process.cmd.trim() || agent_kind(command.trim()).is_none() {
            return Err("session_command_changed");
        }
        Ok(identity)
    }

    fn canonical_uuid(value: &str) -> bool {
        uuid::Uuid::parse_str(value).is_ok_and(|id| id.hyphenated().to_string() == value)
    }

    /// Only established transcript layouts; no filesystem path is traversed.
    /// Codex: openai/codex codex-rs/rollout/src/recorder.rs.
    /// Claude: code.claude.com/docs/en/claude-directory (application data).
    fn transcript_path(kind: &str, path: &Path) -> bool {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return false;
        }
        let Some(stem) = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".jsonl"))
        else {
            return false;
        };
        let Some(parent) = path.parent() else {
            return false;
        };
        match kind {
            "claude" => {
                canonical_uuid(stem)
                    && parent.file_name().is_some()
                    && parent
                        .parent()
                        .and_then(Path::file_name)
                        .is_some_and(|name| name == "projects")
            }
            "codex" => {
                let Some(name) = stem.strip_prefix("rollout-") else {
                    return false;
                };
                let Some(timestamp) = name.get(..19) else {
                    return false;
                };
                if chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%dT%H-%M-%S").is_err()
                    || name.get(19..20) != Some("-")
                {
                    return false;
                }
                let mut ids = name[20..].split('_');
                if !ids.next().is_some_and(canonical_uuid)
                    || ids.next().is_some_and(|id| !canonical_uuid(id))
                    || ids.next().is_some()
                {
                    return false;
                }
                if parent.file_name().is_some_and(|name| name == "sessions") {
                    return true;
                }
                let parts: Vec<_> = parent.components().rev().take(4).collect();
                parts.len() == 4
                    && parts[0].as_os_str() == &timestamp[8..10]
                    && parts[1].as_os_str() == &timestamp[5..7]
                    && parts[2].as_os_str() == &timestamp[..4]
                    && parts[3].as_os_str() == "sessions"
            }
            _ => false,
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct DescriptorIdentity {
        flags: u64,
        mount: u64,
        inode: u64,
    }

    fn descriptor_identity(path: &Path) -> Result<DescriptorIdentity, &'static str> {
        let bytes = read_bounded(path, MAX_FIELD_BYTES)?;
        if bytes.last() != Some(&b'\n') {
            return Err("session_descriptor_info_incomplete");
        }
        let content =
            std::str::from_utf8(&bytes).map_err(|_| "session_descriptor_info_unavailable")?;
        let field = |name: &str, radix: u32| -> Result<u64, &'static str> {
            let mut values = content.lines().filter_map(|line| line.strip_prefix(name));
            let value = values
                .next()
                .ok_or("session_descriptor_info_incomplete")?
                .trim();
            if value.is_empty()
                || !value.bytes().all(|b| b.is_ascii_digit())
                || values.next().is_some()
            {
                return Err("session_descriptor_info_ambiguous");
            }
            u64::from_str_radix(value, radix).map_err(|_| "session_descriptor_info_invalid")
        };
        let identity = DescriptorIdentity {
            flags: field("flags:", 8)?,
            mount: field("mnt_id:", 10)?,
            inode: field("ino:", 10)?,
        };
        if identity.mount == 0 || identity.inode == 0 {
            return Err("session_descriptor_info_invalid");
        }
        Ok(identity)
    }

    type Transcript = ((u64, u64), SystemTime);

    fn inspect_descriptor(
        task: &File,
        fd: u32,
        kind: &str,
        process: &ProcessRecord,
        context: &Context,
    ) -> Result<Option<Transcript>, &'static str> {
        let path = directory_path(task, &format!("fd/{fd}"));
        let target = fs::read_link(&path).map_err(|_| "session_descriptor_link_unavailable")?;
        if !transcript_path(kind, &target) {
            return Ok(None);
        }
        let info = directory_path(task, &format!("fdinfo/{fd}"));
        let before = descriptor_identity(&info)?;
        if !matches!(before.flags & libc::O_ACCMODE as u64, 1 | 2)
            || before.flags & libc::O_PATH as u64 != 0
        {
            return Ok(None);
        }
        // Follow only the kernel's held-descriptor link with O_PATH. Determine
        // its mount from procfs before asking the filesystem for metadata.
        let held = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| "session_descriptor_unavailable")?;
        if !context.filesystems.permits(&held) || mount_id(&held) != Some(before.mount) {
            return Err("session_transcript_filesystem_unavailable");
        }
        let metadata = held
            .metadata()
            .map_err(|_| "session_transcript_metadata_unavailable")?;
        if !metadata.is_file()
            || metadata.uid() != process.uid
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.ino() != before.inode
        {
            return Err("session_transcript_identity_unusable");
        }
        if descriptor_identity(&info)? != before
            || fs::read_link(&path).map_err(|_| "session_descriptor_link_unavailable")? != target
        {
            return Err("session_descriptor_changed");
        }
        Ok(Some((
            (metadata.dev(), metadata.ino()),
            metadata
                .modified()
                .map_err(|_| "session_transcript_mtime_unavailable")?,
        )))
    }

    /// Native Pi treats --session as a file path and --no-session overrides it
    /// (pi_agent_rust src/cli.rs and src/session.rs). Its JSONL descriptor is
    /// closed between saves. Parse NUL-delimited argv, never the flattened
    /// display command. Unknown flags, duplicate selection, hosted launchers
    /// and positional prompts are intentionally unsupported rather than guessed.
    fn native_pi_session_path(command_line: &[u8]) -> Option<PathBuf> {
        let command_line = command_line.strip_suffix(&[0])?;
        let mut arguments = command_line.split(|byte| *byte == 0);
        let executable = std::str::from_utf8(arguments.next()?).ok()?;
        if executable.rsplit('/').next()? != "pi" {
            return None;
        }
        let mut session = None;
        while let Some(argument) = arguments.next() {
            let argument = std::str::from_utf8(argument).ok()?;
            let (name, inline_value) = argument
                .split_once('=')
                .map_or((argument, None), |(name, value)| (name, Some(value)));
            if matches!(
                name,
                "--session"
                    | "--provider"
                    | "--model"
                    | "--api-key"
                    | "--thinking"
                    | "--mode"
                    | "--system-prompt"
                    | "--append-system-prompt"
                    | "--session-dir"
                    | "--session-durability"
                    | "--session-workdir"
            ) {
                let value = match inline_value {
                    Some(value) => value,
                    None => std::str::from_utf8(arguments.next()?).ok()?,
                };
                if value.is_empty() || (inline_value.is_none() && value.starts_with('-')) {
                    return None;
                }
                if name == "--session" && session.replace(PathBuf::from(value)).is_some() {
                    return None;
                }
            } else if inline_value.is_some()
                || !matches!(
                    name,
                    "--print"
                        | "-p"
                        | "--continue"
                        | "-c"
                        | "--resume"
                        | "-r"
                        | "--classic"
                        | "--classic-tui"
                        | "--ftui"
                        | "--no-tools"
                )
            {
                // Includes --no-session, --, help/export/subcommands, and any
                // prompt text containing words that merely resemble options.
                return None;
            }
        }
        let path = session?;
        (path.is_absolute()
            && path
                .extension()
                .is_some_and(|extension| extension == "jsonl")
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))))
        .then_some(path)
    }

    /// No fallback is permitted: even an O_PATH lookup can otherwise consult a
    /// remote filesystem before we can classify the returned descriptor.
    /// RESOLVE_CACHED refuses any lookup needing I/O or revalidation; the held
    /// descriptor is classified separately before its metadata is requested.
    fn open_cached_session_path(root: &File, path: &Path) -> Result<File, &'static str> {
        #[repr(C)]
        struct OpenHow {
            flags: u64,
            mode: u64,
            resolve: u64,
        }
        const RESOLVE_NO_SYMLINKS: u64 = 0x04;
        const RESOLVE_IN_ROOT: u64 = 0x10;
        const RESOLVE_CACHED: u64 = 0x20;
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| "session_explicit_path_invalid")?;
        let how = OpenHow {
            flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_NO_SYMLINKS | RESOLVE_IN_ROOT | RESOLVE_CACHED,
        };
        // SAFETY: the live descriptor, NUL-terminated path and initialized
        // Linux open_how layout remain valid for this synchronous syscall.
        let descriptor = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                root.as_raw_fd(),
                path.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if descriptor < 0 {
            return Err("session_explicit_path_cached_lookup_unavailable");
        }
        // SAFETY: a successful openat2 returns a new owned file descriptor.
        Ok(unsafe { File::from_raw_fd(descriptor as std::os::fd::RawFd) })
    }

    struct SessionProcessView {
        root: File,
        namespace: PathBuf,
        identity: (u64, u64, u64),
    }

    fn pin_session_process_view(
        root: &File,
        context: &Context,
    ) -> Result<SessionProcessView, &'static str> {
        let namespace_path = directory_path(root, "ns/mnt");
        let namespace = fs::read_link(&namespace_path)
            .map_err(|_| "session_explicit_mount_namespace_unavailable")?;
        if namespace
            != fs::read_link("/proc/self/ns/mnt")
                .map_err(|_| "session_explicit_mount_namespace_unavailable")?
        {
            return Err("session_explicit_mount_namespace_unsupported");
        }
        // This is the pinned proc directory's kernel-provided root link, not
        // an arbitrary link from argv. It also handles a same-namespace chroot.
        let view = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(directory_path(root, "root"))
            .map_err(|_| "session_explicit_root_unavailable")?;
        if !context.filesystems.permits(&view) {
            return Err("session_explicit_root_filesystem_unavailable");
        }
        let root_metadata = view
            .metadata()
            .map_err(|_| "session_explicit_root_identity_unavailable")?;
        let identity = (
            root_metadata.dev(),
            root_metadata.ino(),
            mount_id(&view).ok_or("session_explicit_root_identity_unavailable")?,
        );
        Ok(SessionProcessView {
            root: view,
            namespace,
            identity,
        })
    }

    struct ExplicitSessionObservation {
        command_line: Vec<u8>,
        view: SessionProcessView,
        transcript: Transcript,
        // Pin both the process root and transcript across the second
        // observation, preventing inode reuse from disguising replacement.
        _transcript: File,
    }

    fn inspect_explicit_pi_session(
        root: &File,
        process: &ProcessRecord,
        context: &Context,
        deadline: Instant,
    ) -> Result<ExplicitSessionObservation, &'static str> {
        check_budget(deadline)?;
        let command_path = directory_path(root, "cmdline");
        let command_line = read_bounded(&command_path, MAX_FIELD_BYTES)?;
        let path = native_pi_session_path(&command_line)
            .ok_or("session_explicit_argument_unavailable_or_ambiguous")?;
        let view = pin_session_process_view(root, context)?;
        let held = open_cached_session_path(&view.root, &path)?;
        if !context.filesystems.permits(&held) {
            return Err("session_transcript_filesystem_unavailable");
        }
        let metadata = held
            .metadata()
            .map_err(|_| "session_transcript_metadata_unavailable")?;
        if !metadata.is_file()
            || metadata.uid() != process.uid
            || metadata.nlink() != 1
            || metadata.len() == 0
        {
            return Err("session_transcript_identity_unusable");
        }
        let transcript = (
            (metadata.dev(), metadata.ino()),
            metadata
                .modified()
                .map_err(|_| "session_transcript_mtime_unavailable")?,
        );
        if read_bounded(&command_path, MAX_FIELD_BYTES)? != command_line {
            return Err("session_explicit_arguments_changed");
        }
        let after = pin_session_process_view(root, context)?;
        if after.namespace != view.namespace || after.identity != view.identity {
            return Err("session_explicit_process_view_changed");
        }
        check_budget(deadline)?;
        Ok(ExplicitSessionObservation {
            command_line,
            view,
            transcript,
            _transcript: held,
        })
    }

    fn collect_one(
        process: &ProcessRecord,
        window_seconds: u64,
        proc_root: &Path,
        context: &Context,
    ) -> AgentSessionActivity {
        collect_one_with(process, window_seconds, proc_root, context, || {})
    }

    fn record_transcripts(
        result: &mut AgentSessionActivity,
        birth: SystemTime,
        transcripts: BTreeMap<(u64, u64), SystemTime>,
    ) {
        let observed_at = SystemTime::now();
        let mut latest = None;
        for modified in transcripts.into_values() {
            if modified < birth || modified > observed_at {
                result
                    .unavailable
                    .push("session_transcript_mtime_outside_process_lifetime".to_string());
                continue;
            }
            result.transcript_count += 1;
            latest = Some(latest.map_or(modified, |old: SystemTime| old.max(modified)));
        }
        result.identity_verified = true;
        result.observed_at = observed_at.into();
        result.latest_modified_at = latest.map(Into::into);
        if result.transcript_count == 0 {
            result.unavailable.push(
                match result.source {
                    Some(AgentSessionActivitySource::ExplicitSessionArgument) => {
                        "no usable modification time for the explicitly selected session transcript was observed"
                    }
                    _ => {
                        "no identity-bound open writable session transcript was observed; agents may close transcripts between writes"
                    }
                }
                .to_string(),
            );
        }
    }

    fn collect_one_with(
        process: &ProcessRecord,
        window_seconds: u64,
        proc_root: &Path,
        context: &Context,
        before_recheck: impl FnOnce(),
    ) -> AgentSessionActivity {
        let mut result = AgentSessionActivity::unavailable(process, window_seconds, "");
        result.unavailable.clear();
        let observation = (|| -> Result<(), &'static str> {
            if window_seconds == 0 {
                return Err("session transcript activity lookup is disabled by policy");
            }
            check_budget(context.deadline)?;
            let kind = agent_kind(&process.cmd).ok_or("session_agent_unrecognized")?;
            if !matches!(kind, "claude" | "codex" | "pi") {
                return Err("session_transcript_layout_unsupported");
            }
            let deadline = context
                .deadline
                .min(Instant::now() + context.process_budget);
            let root = pin_directory(&proc_root.join(process.pid.0.to_string()))?;
            let before = root_identity(&root, process, context)?;
            let birth = context.birth(before.birth_ticks)?;
            if kind == "pi" {
                result.source = Some(AgentSessionActivitySource::ExplicitSessionArgument);
                let first = inspect_explicit_pi_session(&root, process, context, deadline)?;
                before_recheck();
                let second = inspect_explicit_pi_session(&root, process, context, deadline)?;
                if first.command_line != second.command_line {
                    return Err("session_explicit_arguments_changed");
                }
                if first.view.namespace != second.view.namespace
                    || first.view.identity != second.view.identity
                {
                    return Err("session_explicit_process_view_changed");
                }
                if first.transcript.0 != second.transcript.0 {
                    return Err("session_explicit_transcript_replaced");
                }
                if root_identity(&root, process, context)? != before {
                    return Err("session_process_identity_changed");
                }
                record_transcripts(&mut result, birth, BTreeMap::from([second.transcript]));
                return Ok(());
            }
            result.source = Some(AgentSessionActivitySource::HeldWritableDescriptor);
            let task_dir = directory_path(&root, "task");
            let mut tids = BTreeSet::from([process.pid.0]);
            match fs::read_dir(&task_dir) {
                Ok(entries) => {
                    for entry in entries {
                        if check_budget(deadline).is_err() || tids.len() >= MAX_TASKS {
                            result
                                .unavailable
                                .push("session_task_budget_exhausted".to_string());
                            break;
                        }
                        let tid = entry
                            .ok()
                            .and_then(|entry| entry.file_name().to_str()?.parse::<u32>().ok());
                        match tid {
                            Some(tid) if tid > 0 && tid <= i32::MAX as u32 => {
                                tids.insert(tid);
                            }
                            _ => result
                                .unavailable
                                .push("session_task_entry_unavailable".to_string()),
                        }
                    }
                }
                Err(_) => result
                    .unavailable
                    .push("session_tasks_unavailable".to_string()),
            }
            let mut remaining = MAX_DESCRIPTORS;
            let mut transcripts = BTreeMap::new();
            // Inspect the leader first: most threads share this descriptor table.
            let ordered = std::iter::once(process.pid.0)
                .chain(tids.into_iter().filter(|tid| *tid != process.pid.0));
            for tid in ordered {
                if check_budget(deadline).is_err() || remaining == 0 {
                    result
                        .unavailable
                        .push("session_descriptor_budget_exhausted".to_string());
                    break;
                }
                let task_result = (|| -> Result<BTreeMap<(u64, u64), SystemTime>, &'static str> {
                    let task = pin_directory(&task_dir.join(tid.to_string()))?;
                    let (task_before, _) = task_identity(&task, tid, process)?;
                    let entries = fs::read_dir(directory_path(&task, "fd"))
                        .map_err(|_| "session_descriptor_table_unavailable")?;
                    let mut found = BTreeMap::new();
                    for entry in entries {
                        if check_budget(deadline).is_err() || remaining == 0 {
                            result
                                .unavailable
                                .push("session_descriptor_budget_exhausted".to_string());
                            break;
                        }
                        remaining -= 1;
                        let fd = entry
                            .ok()
                            .and_then(|entry| entry.file_name().to_str()?.parse::<u32>().ok());
                        let Some(fd) = fd.filter(|fd| *fd <= i32::MAX as u32) else {
                            result
                                .unavailable
                                .push("session_descriptor_entry_unavailable".to_string());
                            continue;
                        };
                        match inspect_descriptor(&task, fd, kind, process, context) {
                            Ok(Some((identity, modified))) => {
                                found.insert(identity, modified);
                            }
                            Ok(None) => {}
                            Err(reason) => result.unavailable.push(reason.to_string()),
                        }
                    }
                    let (task_after, _) = task_identity(&task, tid, process)?;
                    if task_before != task_after {
                        return Err("session_task_identity_changed");
                    }
                    Ok(found)
                })();
                match task_result {
                    Ok(found) => transcripts.extend(found),
                    Err(reason) => result.unavailable.push(reason.to_string()),
                }
            }
            // A positive observation still needs a final bounded root check
            // after a descriptor budget expires. Never reuse a replaced process.
            before_recheck();
            if root_identity(&root, process, context)? != before {
                return Err("session_process_identity_changed");
            }
            record_transcripts(&mut result, birth, transcripts);
            Ok(())
        })();
        if let Err(reason) = observation {
            result.identity_verified = false;
            result.transcript_count = 0;
            result.latest_modified_at = None;
            result.unavailable.push(reason.to_string());
        }
        result.unavailable.sort();
        result.unavailable.dedup();
        result
    }

    pub(super) fn collect(
        processes: &[&ProcessRecord],
        window_seconds: u64,
    ) -> BTreeMap<u32, AgentSessionActivity> {
        let roots: Vec<_> = processes
            .iter()
            .copied()
            .filter(|process| agent_kind(&process.cmd).is_some())
            .collect();
        if roots.is_empty() {
            return BTreeMap::new();
        }
        let context = if window_seconds == 0 {
            Err("session transcript activity lookup is disabled by policy")
        } else {
            Context::load(Instant::now() + SCAN_BUDGET)
        };
        roots
            .into_iter()
            .map(|process| {
                let observation = match &context {
                    Ok(context) => {
                        collect_one(process, window_seconds, Path::new("/proc"), context)
                    }
                    Err(reason) => {
                        AgentSessionActivity::unavailable(process, window_seconds, reason)
                    }
                };
                (process.pid.0, observation)
            })
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::collect::ProcessState;
        use pt_common::{ProcessId, StartId};
        use std::path::PathBuf;

        const BOOT: &str = "ebaf61d7-e8b6-4f06-a845-4376238330f0";
        const SESSION: &str = "019c017a-84b0-7710-8bba-47ea1175fee3";

        fn raw_arguments(arguments: &[&str]) -> Vec<u8> {
            arguments
                .iter()
                .flat_map(|argument| argument.bytes().chain(std::iter::once(0)))
                .collect()
        }

        fn assert_cached_lookup_unavailable(observed: &AgentSessionActivity) {
            assert_eq!(observed.recently_modified(), None, "{observed:?}");
            assert!(!observed.identity_verified);
            assert_eq!(observed.transcript_count, 0);
            assert!(observed.latest_modified_at.is_none());
            assert_eq!(
                observed.unavailable,
                ["session_explicit_path_cached_lookup_unavailable"]
            );
        }

        struct Fixture {
            _directory: tempfile::TempDir,
            proc_root: PathBuf,
            transcript: PathBuf,
            process: ProcessRecord,
            context: Context,
        }

        impl Fixture {
            fn new() -> Self {
                let directory = tempfile::tempdir().unwrap();
                let proc_root = directory.path().join("proc");
                let transcript = directory.path().join(format!(
                    "sessions/2026/01/27/rollout-2026-01-27T12-30-00-{SESSION}.jsonl"
                ));
                fs::create_dir_all(transcript.parent().unwrap()).unwrap();
                fs::write(&transcript, b"{}\n").unwrap();
                let held = File::open(&transcript).unwrap();
                let uid = held.metadata().unwrap().uid();
                let mount = mount_id(&held).unwrap();
                let process = ProcessRecord {
                    pid: ProcessId(4242),
                    ppid: ProcessId(1),
                    uid,
                    user: "fixture".to_string(),
                    pgid: Some(4242),
                    sid: Some(4242),
                    start_id: StartId::from_linux(BOOT, 100, 4242),
                    comm: "codex".to_string(),
                    cmd: "codex exec review".to_string(),
                    state: ProcessState::Sleeping,
                    cpu_percent: 0.0,
                    rss_bytes: 4096,
                    vsz_bytes: 8192,
                    tty: None,
                    start_time_unix: 1_600_000_001,
                    elapsed: Duration::from_secs(3600),
                    source: "fixture".to_string(),
                    container_info: None,
                };
                let context = Context {
                    boot: BOOT.to_string(),
                    boot_time: UNIX_EPOCH + Duration::from_secs(1_600_000_000),
                    ticks_per_second: 100,
                    filesystems: FilesystemGuard {
                        mounts: BTreeMap::from([(mount, true)]),
                    },
                    deadline: Instant::now() + Duration::from_secs(10),
                    process_budget: Duration::from_secs(10),
                };
                let result = Self {
                    _directory: directory,
                    proc_root,
                    transcript,
                    process,
                    context,
                };
                result.write_identity(&result.root(), 4242);
                fs::write(result.root().join("cmdline"), b"codex\0exec\0review\0").unwrap();
                result.add_task(4242);
                result.add_descriptor(4242, 3, 2);
                result
            }

            fn explicit_pi() -> Self {
                let mut fixture = Self::new();
                fixture.process.comm = "pi".to_string();
                let path = fixture.transcript.to_str().unwrap().to_string();
                fixture.arguments(&["pi", "--session", &path]);
                fixture.write_identity(&fixture.root(), 4242);
                // The explicit source must work with no descriptor table to
                // inspect: native Pi closes its transcript between saves.
                fs::rename(
                    fixture.root().join("task"),
                    fixture.root().join("unused_descriptor_fixture"),
                )
                .unwrap();
                fs::create_dir_all(fixture.root().join("ns")).unwrap();
                std::os::unix::fs::symlink(
                    fs::read_link("/proc/self/ns/mnt").unwrap(),
                    fixture.root().join("ns/mnt"),
                )
                .unwrap();
                std::os::unix::fs::symlink("/", fixture.root().join("root")).unwrap();
                let root = pin_directory(Path::new("/")).unwrap();
                fixture
                    .context
                    .filesystems
                    .mounts
                    .insert(mount_id(&root).unwrap(), true);
                fixture
            }

            fn arguments(&mut self, arguments: &[&str]) {
                self.process.cmd = arguments.join(" ");
                fs::write(self.root().join("cmdline"), raw_arguments(arguments)).unwrap();
            }

            fn root(&self) -> PathBuf {
                self.proc_root.join("4242")
            }

            fn task(&self, tid: u32) -> PathBuf {
                self.root().join("task").join(tid.to_string())
            }

            fn write_identity(&self, path: &Path, tid: u32) {
                fs::create_dir_all(path).unwrap();
                let mut fields = ["0"; 24];
                fields[0] = "S";
                fields[1] = "1";
                fields[2] = "4242";
                fields[3] = "4242";
                fields[19] = "100";
                fs::write(
                    path.join("stat"),
                    format!("{tid} ({}) {}\n", self.process.comm, fields.join(" ")),
                )
                .unwrap();
                let uid = self.process.uid;
                fs::write(
                    path.join("status"),
                    format!("Tgid:\t4242\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
                )
                .unwrap();
            }

            fn add_task(&self, tid: u32) {
                let task = self.task(tid);
                self.write_identity(&task, tid);
                fs::create_dir_all(task.join("fd")).unwrap();
                fs::create_dir_all(task.join("fdinfo")).unwrap();
            }

            fn add_descriptor(&self, tid: u32, fd: u32, flags: u64) {
                let task = self.task(tid);
                std::os::unix::fs::symlink(&self.transcript, task.join(format!("fd/{fd}")))
                    .unwrap();
                self.write_descriptor_info(tid, fd, flags);
            }

            fn write_descriptor_info(&self, tid: u32, fd: u32, flags: u64) {
                let held = File::open(&self.transcript).unwrap();
                let mount = mount_id(&held).unwrap();
                let inode = held.metadata().unwrap().ino();
                fs::write(
                    self.task(tid).join(format!("fdinfo/{fd}")),
                    format!("flags:\t{flags:o}\nmnt_id:\t{mount}\nino:\t{inode}\n"),
                )
                .unwrap();
            }

            fn modified(&self, when: SystemTime) {
                File::options()
                    .write(true)
                    .open(&self.transcript)
                    .unwrap()
                    .set_modified(when)
                    .unwrap();
            }

            fn observe(&self, window_seconds: u64) -> AgentSessionActivity {
                collect_one(
                    &self.process,
                    window_seconds,
                    &self.proc_root,
                    &self.context,
                )
            }
        }

        #[test]
        fn native_pi_session_arguments_reject_ambiguous_launches() {
            for arguments in [
                vec!["pi", "--session", "/custom/selected.jsonl"],
                vec!["/home/u/bin/pi", "--session=/custom/selected.jsonl"],
                vec![
                    "pi",
                    "--mode",
                    "rpc",
                    "--provider",
                    "anthropic",
                    "--session",
                    "/custom/selected.jsonl",
                    "--continue",
                ],
                vec![
                    "pi",
                    "--session",
                    "/custom/selected.jsonl",
                    "--system-prompt",
                    "a prompt with spaces and --session in its text",
                ],
            ] {
                assert_eq!(
                    native_pi_session_path(&raw_arguments(&arguments)),
                    Some(PathBuf::from("/custom/selected.jsonl")),
                    "{arguments:?}"
                );
            }
            assert_eq!(
                native_pi_session_path(&raw_arguments(&[
                    "pi",
                    "--session",
                    "/custom/会話 with spaces.jsonl",
                ])),
                Some(PathBuf::from("/custom/会話 with spaces.jsonl"))
            );
            for arguments in [
                vec!["pi"],
                vec!["pi", "--session"],
                vec!["pi", "--session="],
                vec!["pi", "--session", "selected.jsonl"],
                vec!["pi", "--session", "a-session-id"],
                vec!["pi", "--session", "/custom/session.sqlite"],
                vec!["pi", "--session", "/custom/../selected.jsonl"],
                vec!["pi", "--session", "/a.jsonl", "--session=/b.jsonl"],
                vec!["pi", "--no-session", "--session", "/a.jsonl"],
                vec!["pi", "--session", "/a.jsonl", "--no-session"],
                vec!["pi", "--", "--session", "/a.jsonl"],
                vec!["pi", "review", "--session", "/a.jsonl"],
                vec!["pi", "--session", "/a.jsonl", "review this"],
                vec!["pi", "--session", "/a.jsonl", "--unknown-option"],
                vec!["pi", "--system-prompt", "--session", "/a.jsonl"],
                vec!["pi", "--system-prompt=--session /a.jsonl"],
                vec!["pi --session /a.jsonl"],
                vec![
                    "node",
                    "/pkg/@mariozechner/pi-coding-agent/dist/cli.js",
                    "--session",
                    "/a.jsonl",
                ],
                vec!["bash", "-c", "pi --session /a.jsonl"],
            ] {
                assert_eq!(
                    native_pi_session_path(&raw_arguments(&arguments)),
                    None,
                    "{arguments:?}"
                );
            }
            assert_eq!(native_pi_session_path(b"pi\0--session\0/a.jsonl"), None);
        }

        #[test]
        fn explicit_pi_transcript_is_observed_without_open_descriptors() {
            let cached_lookup = super::super::cached_session_lookup_available_for_test();
            let fixture = Fixture::explicit_pi();
            assert!(!fixture.root().join("task").exists());
            let observed = fixture.observe(1800);
            if cached_lookup {
                assert!(observed.matches_record(&fixture.process), "{observed:?}");
                assert_eq!(observed.recently_modified(), Some(true));
                assert_eq!(observed.transcript_count, 1);
            } else {
                assert_cached_lookup_unavailable(&observed);
            }
            assert_eq!(
                observed.source,
                Some(AgentSessionActivitySource::ExplicitSessionArgument)
            );
            let encoded = serde_json::to_string(&observed).unwrap();
            assert!(!encoded.contains(fixture.transcript.to_str().unwrap()));
            assert!(!encoded.contains(SESSION));
            fixture.modified(SystemTime::now() - Duration::from_secs(3600));
            let stale = fixture.observe(1800);
            if cached_lookup {
                assert_eq!(stale.recently_modified(), Some(false));
            } else {
                assert_cached_lookup_unavailable(&stale);
            }
            fixture.modified(SystemTime::now() + Duration::from_secs(1));
            assert_eq!(fixture.observe(1800).recently_modified(), None);
            fixture.modified(fixture.context.boot_time);
            assert_eq!(fixture.observe(1800).recently_modified(), None);
            assert_eq!(fixture.observe(0).recently_modified(), None);
        }

        #[test]
        fn explicit_pi_arguments_and_path_replacement_are_rechecked() {
            let cached_lookup = super::super::cached_session_lookup_available_for_test();
            let mut fixture = Fixture::explicit_pi();
            let path = fixture.transcript.to_str().unwrap().to_string();
            fixture.arguments(&[
                "pi",
                "--session",
                &path,
                "--system-prompt=hello --model example",
            ]);
            let changed = raw_arguments(&[
                "pi",
                "--session",
                &path,
                "--system-prompt=hello",
                "--model",
                "example",
            ]);
            // Both argv arrays are supported and flatten to the same text.
            // Only byte-exact argv comparison detects the changed boundaries.
            assert_eq!(
                native_pi_session_path(&changed),
                Some(fixture.transcript.clone())
            );
            let observed = collect_one_with(
                &fixture.process,
                1800,
                &fixture.proc_root,
                &fixture.context,
                || fs::write(fixture.root().join("cmdline"), &changed).unwrap(),
            );
            assert_eq!(observed.recently_modified(), None);
            if cached_lookup {
                assert!(observed
                    .unavailable
                    .iter()
                    .any(|reason| reason == "session_explicit_arguments_changed"));
            } else {
                assert_cached_lookup_unavailable(&observed);
            }

            let fixture = Fixture::explicit_pi();
            let observed = collect_one_with(
                &fixture.process,
                1800,
                &fixture.proc_root,
                &fixture.context,
                || {
                    fs::rename(
                        &fixture.transcript,
                        fixture.transcript.with_extension("previous"),
                    )
                    .unwrap();
                    fs::write(&fixture.transcript, b"{\"replacement\":true}\n").unwrap();
                },
            );
            assert_eq!(observed.recently_modified(), None);
            if cached_lookup {
                assert!(observed
                    .unavailable
                    .iter()
                    .any(|reason| reason == "session_explicit_transcript_replaced"));
            } else {
                assert_cached_lookup_unavailable(&observed);
            }
        }

        #[test]
        fn explicit_pi_symlinks_wrong_owner_and_unsafe_filesystems_stay_unknown() {
            let mut fixture = Fixture::explicit_pi();
            let link = fixture.transcript.with_file_name("linked.jsonl");
            std::os::unix::fs::symlink(&fixture.transcript, &link).unwrap();
            fixture.arguments(&["pi", "--session", link.to_str().unwrap()]);
            assert_eq!(fixture.observe(1800).recently_modified(), None);
            let path = fixture.transcript.to_str().unwrap().to_string();
            fixture.arguments(&["pi", "--session", &path]);
            fixture.process.uid = fixture.process.uid.wrapping_add(1);
            fixture.write_identity(&fixture.root(), 4242);
            assert_eq!(fixture.observe(1800).recently_modified(), None);

            let mut fixture = Fixture::explicit_pi();
            for allowed in fixture.context.filesystems.mounts.values_mut() {
                *allowed = false;
            }
            assert_eq!(fixture.observe(1800).recently_modified(), None);
        }

        #[test]
        fn explicit_pi_root_and_namespace_changes_stay_unknown() {
            let cached_lookup = super::super::cached_session_lookup_available_for_test();
            for change_namespace in [false, true] {
                let fixture = Fixture::explicit_pi();
                let observed = collect_one_with(
                    &fixture.process,
                    1800,
                    &fixture.proc_root,
                    &fixture.context,
                    || {
                        if change_namespace {
                            fs::rename(
                                fixture.root().join("ns/mnt"),
                                fixture.root().join("ns/previous"),
                            )
                            .unwrap();
                            std::os::unix::fs::symlink("mnt:[0]", fixture.root().join("ns/mnt"))
                                .unwrap();
                        } else {
                            fs::rename(
                                fixture.root().join("root"),
                                fixture.root().join("previous_root"),
                            )
                            .unwrap();
                            std::os::unix::fs::symlink(
                                fixture.proc_root.parent().unwrap(),
                                fixture.root().join("root"),
                            )
                            .unwrap();
                        }
                    },
                );
                assert_eq!(observed.recently_modified(), None, "{observed:?}");
                assert!(!observed.identity_verified);
                if !cached_lookup {
                    assert_cached_lookup_unavailable(&observed);
                }
            }
        }

        #[test]
        fn transcript_layouts_are_specific_and_support_custom_roots() {
            for path in [
                format!("/custom/sessions/2026/01/27/rollout-2026-01-27T12-30-00-{SESSION}.jsonl"),
                format!("/custom/sessions/rollout-2026-01-27T12-30-00-{SESSION}_{BOOT}.jsonl"),
            ] {
                assert!(transcript_path("codex", Path::new(&path)), "{path}");
            }
            assert!(transcript_path(
                "claude",
                Path::new(&format!("/custom/projects/-workspace/{SESSION}.jsonl"))
            ));
            for path in [
                "/tmp/history.jsonl".to_string(),
                format!("projects/-workspace/{SESSION}.jsonl"),
                format!("/custom/projects/-workspace/{SESSION}.jsonl (deleted)"),
                format!("/custom/sessions/2026/01/28/rollout-2026-01-27T12-30-00-{SESSION}.jsonl"),
                format!("/custom/sessions/rollout-2026-99-27T12-30-00-{SESSION}.jsonl"),
                "/custom/sessions/rollout-2026-01-27T12-30-00-not-an-id.jsonl".to_string(),
            ] {
                assert!(!transcript_path("codex", Path::new(&path)), "{path}");
                assert!(!transcript_path("claude", Path::new(&path)), "{path}");
            }
            assert!(!transcript_path(
                "gemini",
                Path::new(&format!("/custom/projects/-workspace/{SESSION}.jsonl"))
            ));
        }

        #[test]
        fn held_writable_transcript_is_bound_deduplicated_and_private() {
            let fixture = Fixture::new();
            fixture.add_task(4243);
            fixture.add_descriptor(4243, 3, 2);
            // Unreadable evidence on another descriptor must not erase a
            // separately verified positive observation.
            fs::write(fixture.task(4242).join("fd/9"), b"not a descriptor link").unwrap();
            let observation = fixture.observe(1800);
            assert!(observation.matches_record(&fixture.process));
            assert_eq!(observation.transcript_count, 1);
            assert_eq!(observation.recently_modified(), Some(true));
            assert!(!observation.unavailable.is_empty());
            let encoded = serde_json::to_string(&observation).unwrap();
            assert!(!encoded.contains(SESSION));
            assert!(!encoded.contains(fixture.transcript.to_str().unwrap()));
            let decoded: AgentSessionActivity = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded.recently_modified(), Some(true));

            fixture.modified(SystemTime::now() - Duration::from_secs(3600));
            let stale_partial = fixture.observe(1800);
            assert_eq!(stale_partial.transcript_count, 1);
            assert!(!stale_partial.unavailable.is_empty());
            assert_eq!(stale_partial.recently_modified(), None);
        }

        #[test]
        fn stale_future_prebirth_disabled_and_unavailable_are_distinct() {
            let fixture = Fixture::new();
            fixture.modified(SystemTime::now() - Duration::from_secs(3600));
            assert_eq!(fixture.observe(1800).recently_modified(), Some(false));
            fixture.modified(SystemTime::now() + Duration::from_secs(3600));
            assert_eq!(fixture.observe(1800).recently_modified(), None);
            fixture.modified(fixture.context.boot_time);
            assert_eq!(fixture.observe(1800).recently_modified(), None);
            fixture.modified(SystemTime::now());
            assert_eq!(fixture.observe(0).recently_modified(), None);
            fixture.write_descriptor_info(4242, 3, 0);
            assert_eq!(fixture.observe(1800).recently_modified(), None);
            fixture.write_descriptor_info(4242, 3, 2);
            fs::write(fixture.task(4242).join("fdinfo/3"), b"flags:\t2\n").unwrap();
            assert_eq!(fixture.observe(1800).recently_modified(), None);
        }

        #[test]
        fn filesystem_and_inode_ambiguity_fail_closed() {
            let mut fixture = Fixture::new();
            for allowed in fixture.context.filesystems.mounts.values_mut() {
                *allowed = false;
            }
            assert_eq!(fixture.observe(1800).recently_modified(), None);
            for allowed in fixture.context.filesystems.mounts.values_mut() {
                *allowed = true;
            }
            fs::hard_link(
                &fixture.transcript,
                fixture.transcript.with_extension("linked"),
            )
            .unwrap();
            assert_eq!(fixture.observe(1800).recently_modified(), None);
        }

        #[test]
        fn transcript_owner_must_match_the_verified_process() {
            let mut fixture = Fixture::new();
            fixture.process.uid = fixture.process.uid.wrapping_add(1);
            fixture.write_identity(&fixture.root(), 4242);
            fixture.write_identity(&fixture.task(4242), 4242);
            assert_eq!(fixture.observe(1800).recently_modified(), None);
        }

        #[test]
        fn root_replacement_reparenting_exec_and_exhausted_budget_are_unknown() {
            let fixture = Fixture::new();
            let mut changed = fixture.process.clone();
            changed.ppid = ProcessId(2);
            assert_eq!(
                collect_one(&changed, 1800, &fixture.proc_root, &fixture.context)
                    .recently_modified(),
                None
            );
            changed = fixture.process.clone();
            changed.start_id = StartId::from_linux(BOOT, 101, 4242);
            assert_eq!(
                collect_one(&changed, 1800, &fixture.proc_root, &fixture.context)
                    .recently_modified(),
                None
            );
            let raced = collect_one_with(
                &fixture.process,
                1800,
                &fixture.proc_root,
                &fixture.context,
                || fs::write(fixture.root().join("cmdline"), b"codex\0exec\0other\0").unwrap(),
            );
            assert!(!raced.identity_verified);
            assert_eq!(raced.transcript_count, 0);
            assert_eq!(raced.recently_modified(), None);
            let mut fixture = Fixture::new();
            fixture.context.deadline = Instant::now();
            assert_eq!(fixture.observe(1800).recently_modified(), None);
        }
    }
}

/// Seconds since the terminal `tty` (as `ps` reports it: `pts/3`, `ttys003`) last
/// saw input or output: the device's atime/mtime, which is what `w` shows as IDLE.
/// `None` when the device cannot be stat'ed.
#[cfg(unix)]
pub fn tty_idle_seconds(tty: &str) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    let path = if tty.starts_with('/') {
        std::path::PathBuf::from(tty)
    } else {
        std::path::Path::new("/dev").join(tty)
    };
    let md = std::fs::metadata(path).ok()?;
    let last_io = md.atime().max(md.mtime());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    Some(now.saturating_sub(last_io).max(0) as u64)
}

/// PIDs of this pt process and all of its ancestors (the invoking shell, agent CLI,
/// tmux pane, multiplexer...). pt must never recommend killing its own caller chain.
pub fn invoker_chain_pids(processes: &[ProcessRecord]) -> HashSet<u32> {
    let parent_of: std::collections::HashMap<u32, u32> =
        processes.iter().map(|p| (p.pid.0, p.ppid.0)).collect();
    let mut chain = HashSet::new();
    let mut pid = std::process::id();
    while pid > 1 && chain.insert(pid) {
        match parent_of.get(&pid) {
            Some(&ppid) => pid = ppid,
            None => break,
        }
    }
    chain
}

/// Whether a username denotes the superuser (the only protected user relaxed for
/// login-session workloads).
pub fn is_root_user(user: &str) -> bool {
    user.eq_ignore_ascii_case("root")
}

/// Where a macOS process sits, for built-in protection (macOS has no cgroups).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacPlacement {
    /// Part of the system or a GUI app: protected, with the reason.
    System(&'static str),
    /// Owned by a real user and outside Apple's system paths and app bundles: a
    /// candidate even when reparented to launchd (PID 1), like a Linux session workload.
    UserWorkload,
}

/// Classify a macOS process from its owner and executable.
///
/// - `root` and system role accounts (`_windowserver`, `_spotlight`, `daemon`,
///   `nobody`) run the launchd system domain;
/// - Apple platform binaries live under /System, /usr/libexec, /usr/sbin, /sbin,
///   /Library/Apple (not /usr/bin: user scripts run through /usr/bin/python3 etc.);
/// - anything inside a `.app` bundle is a GUI app or one of its helpers.
///
/// Everything else (a user's dev server, script, or orphan whose terminal closed) is
/// evaluated. User launchd agents land here too: they are process-group leaders, so
/// they carry no orphan evidence, and restart/stop goes through launchctl.
pub fn macos_placement(user: &str, comm: &str, cmd: &str) -> MacPlacement {
    const APPLE_PATHS: [&str; 5] = [
        "/System/",
        "/usr/libexec/",
        "/usr/sbin/",
        "/sbin/",
        "/Library/Apple/",
    ];
    if is_root_user(user) || user.starts_with('_') || matches!(user, "daemon" | "nobody") {
        return MacPlacement::System("macOS system domain (root or a system role account)");
    }
    let exe = cmd.split_whitespace().next().unwrap_or("");
    let from_apple = |s: &str| APPLE_PATHS.iter().any(|p| s.starts_with(p));
    if from_apple(comm) || from_apple(exe) {
        return MacPlacement::System("Apple platform binary");
    }
    if comm.contains(".app/Contents/") || cmd.contains(".app/Contents/") {
        return MacPlacement::System("macOS app bundle (GUI app or one of its helpers)");
    }
    MacPlacement::UserWorkload
}

/// Rule name for macOS system-domain, Apple and app-bundle processes.
pub const MACOS_SYSTEM_RULE: &str = "builtin.macos_system";

/// Why a supervised service is protected.
pub const SUPERVISED_SERVICE_NOTES: &str =
    "supervised by systemd or a container runtime; stop the unit instead";

/// Where built-in protection places a process. The scan-time filter and the
/// plan-time policy enforcer both decide through [`builtin_placement`], so a process
/// the scan evaluates is not blocked later for its placement (the enforcer used to
/// know only cgroup roles, which macOS never has, and blocked every macOS orphan
/// through `never_kill_ppid`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinPlacement {
    /// Supervised by systemd or a container runtime: protected (stop the unit instead).
    SupervisedService,
    /// macOS system domain, Apple platform binary or app bundle: protected.
    MacSystem(&'static str),
    /// Started by a person or agent (login session, transient scope, or a macOS
    /// user's own process): exempt from `never_kill_ppid`, and from `protected_users`
    /// for root, because an orphan reparented to PID 1 is a candidate.
    UserWorkload,
    /// No placement known (Linux without systemd cgroups: cgroup v1, a container's
    /// root namespace; a macOS process whose owner is unknown). The configured
    /// guardrails apply unchanged: children of PID 1 stay protected by
    /// `never_kill_ppid` and root by `protected_users`.
    Unplaced,
}

/// Place a process from its cgroup role and, on macOS (no cgroups), its owner and
/// executable. See [`BuiltinPlacement`].
pub fn builtin_placement(
    role: super::cgroup::CgroupRole,
    user: &str,
    comm: &str,
    cmd: &str,
) -> BuiltinPlacement {
    placement_on(cfg!(target_os = "macos"), role, user, comm, cmd)
}

fn placement_on(
    macos: bool,
    role: super::cgroup::CgroupRole,
    user: &str,
    comm: &str,
    cmd: &str,
) -> BuiltinPlacement {
    if role.is_supervised_service() {
        return BuiltinPlacement::SupervisedService;
    }
    if role.is_user_workload() {
        return BuiltinPlacement::UserWorkload;
    }
    if macos && role == super::cgroup::CgroupRole::Unknown && !user.is_empty() {
        return match macos_placement(user, comm, cmd) {
            MacPlacement::System(notes) => BuiltinPlacement::MacSystem(notes),
            MacPlacement::UserWorkload => BuiltinPlacement::UserWorkload,
        };
    }
    BuiltinPlacement::Unplaced
}

/// Name of the built-in rule for database / web / message servers.
pub const SERVICE_DAEMON_RULE: &str = "builtin.service_daemon";

/// Nearest matching ancestors in one captured census. The inclusive answer
/// for each examined parent is cached, including missing or cyclic branches.
/// Each distinct record is classified at most once across all queries.
pub struct ScanAncestors<'a> {
    records: &'a HashMap<u32, &'a ProcessRecord>,
    matches: fn(&ProcessRecord) -> bool,
    inclusive: HashMap<u32, Option<u32>>,
}

impl<'a> ScanAncestors<'a> {
    pub fn new(
        records: &'a HashMap<u32, &'a ProcessRecord>,
        matches: fn(&ProcessRecord) -> bool,
    ) -> Self {
        Self {
            records,
            matches,
            inclusive: HashMap::new(),
        }
    }

    pub fn nearest(&mut self, pid: u32) -> Option<&'a ProcessRecord> {
        let mut current = self.records.get(&pid)?.ppid.0;
        let mut path = Vec::new();
        let found = loop {
            if current <= 1 {
                break None;
            }
            if let Some(&known) = self.inclusive.get(&current) {
                break known;
            }
            // A revisit before this walk finishes is a cycle. Leave it
            // unmatched unless a matching record was actually observed.
            self.inclusive.insert(current, None);
            path.push(current);
            let Some(record) = self.records.get(&current) else {
                break None;
            };
            if (self.matches)(record) {
                break Some(current);
            }
            current = record.ppid.0;
        };
        for traversed in path {
            self.inclusive.insert(traversed, found);
        }
        found
            .filter(|&ancestor| ancestor != pid)
            .and_then(|ancestor| self.records.get(&ancestor).copied())
    }
}

/// Whether a process is a service or shared agent-coordination daemon.
pub fn is_service_daemon(comm: &str, cmd: &str) -> bool {
    builtin_protection_match(comm, cmd)
        .is_some_and(|(rule, _)| matches!(rule, SERVICE_DAEMON_RULE | "builtin.agent_coordination"))
}

/// Nearest ancestor of `pid` that is a service daemon (`(pid, comm)`), walking the
/// parent chain with `parent_of`/`identity_of`. Workers and plugins inherit their
/// server's protection by parent identity, whatever title they give themselves.
fn service_ancestor_with(
    pid: u32,
    parent_of: impl Fn(u32) -> Option<u32>,
    identity_of: impl Fn(u32) -> Option<(String, String)>,
) -> Option<(u32, String)> {
    let mut seen = HashSet::from([pid]);
    let mut current = pid;
    loop {
        let parent = parent_of(current)?;
        if parent <= 1 || !seen.insert(parent) {
            return None;
        }
        if let Some((comm, cmd)) = identity_of(parent) {
            if is_service_daemon(&comm, &cmd) {
                return Some((parent, comm));
            }
        }
        current = parent;
    }
}

/// [`service_ancestor_with`] over a scan (no extra syscalls).
pub fn service_ancestor(
    pid: u32,
    processes: &std::collections::HashMap<u32, &ProcessRecord>,
) -> Option<(u32, String)> {
    ScanAncestors::new(processes, |process| {
        is_service_daemon(&process.comm, &process.cmd)
    })
    .nearest(pid)
    .map(|record| (record.pid.0, record.comm.clone()))
}

/// [`service_ancestor_with`] against live OS state, for apply-time checks.
pub fn live_service_ancestor(pid: u32) -> Option<(u32, String)> {
    service_ancestor_with(pid, live_ppid, live_identity)
}

/// `(comm, cmdline)` of a live process.
fn live_identity(pid: u32) -> Option<(String, String)> {
    #[cfg(target_os = "linux")]
    {
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
        let raw = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        let cmd = String::from_utf8_lossy(&raw)
            .split('\0')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        Some((comm.trim_end().to_string(), cmd))
    }
    #[cfg(target_os = "macos")]
    {
        // ps `comm=` is the executable path; the rule accepts a leading path.
        super::macos::read_process_snapshot(pid).map(|s| (s.comm.clone(), s.comm))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

/// Parent PID of a live process, read from the OS.
fn live_ppid(pid: u32) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        super::proc_parsers::parse_proc_stat(pid).map(|s| s.ppid)
    }
    #[cfg(target_os = "macos")]
    {
        super::macos::read_process_snapshot(pid).map(|s| s.ppid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

/// Live version of [`invoker_chain_pids`] for apply-time checks (no scan available).
pub fn live_invoker_chain_pids() -> HashSet<u32> {
    let mut chain = HashSet::new();
    let mut pid = std::process::id();
    while pid > 1 && chain.insert(pid) {
        match live_ppid(pid) {
            Some(ppid) => pid = ppid,
            None => break,
        }
    }
    chain
}

/// Truncate command line for logging (avoid huge logs).
fn truncate_cmd(cmd: &str, max_len: usize) -> String {
    if cmd.len() <= max_len {
        cmd.to_string()
    } else {
        // Cut on a char boundary: byte slicing panics on multi-byte UTF-8 command lines.
        let mut end = max_len.saturating_sub(3);
        while end > 0 && !cmd.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &cmd[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pt_common::{ProcessId, StartId};
    use std::time::Duration;

    #[cfg(target_os = "linux")]
    fn fuse_device_in_fd_table(directory: &std::path::Path) -> Option<bool> {
        fuse_device_table_snapshot(
            directory,
            &mut FuseInspectionBudget::default(),
            &mut FuseDescriptorTable::new(),
        )
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fuse_device_detection_reads_descriptor_links_without_following_them() {
        let table = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/dev/null", table.path().join("0")).unwrap();
        std::os::unix::fs::symlink("socket:[123]", table.path().join("1")).unwrap();
        std::os::unix::fs::symlink("/unavailable/mount/file", table.path().join("2")).unwrap();
        assert_eq!(fuse_device_in_fd_table(table.path()), Some(false));

        // The device need not exist in the test namespace: only procfs link
        // text is read, never the potentially blocked descriptor target.
        std::os::unix::fs::symlink("/dev/fuse", table.path().join("3")).unwrap();
        assert_eq!(fuse_device_in_fd_table(table.path()), Some(true));

        let unlinked = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/dev/fuse (deleted)", unlinked.path().join("0")).unwrap();
        assert_eq!(fuse_device_in_fd_table(unlinked.path()), Some(true));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fuse_device_detection_preserves_incomplete_evidence() {
        let table = tempfile::tempdir().unwrap();
        assert_eq!(fuse_device_in_fd_table(&table.path().join("missing")), None);
        std::fs::write(table.path().join("0"), b"not a procfs descriptor link").unwrap();
        assert_eq!(fuse_device_in_fd_table(table.path()), None);
        // A positively identified device remains sufficient to refuse an
        // action, even if another descriptor could not be read.
        std::os::unix::fs::symlink("/dev/fuse", table.path().join("1")).unwrap();
        assert_eq!(fuse_device_in_fd_table(table.path()), Some(true));
        assert_eq!(holds_fuse_device(u32::MAX), None);

        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied,
        ] {
            assert_eq!(
                fuse_device_from_link_targets([
                    Err(std::io::Error::from(kind)),
                    Ok(std::path::PathBuf::from("/dev/null")),
                ]),
                None
            );
            for positive_first in [false, true] {
                let mut targets = vec![
                    Err(std::io::Error::from(kind)),
                    Ok(std::path::PathBuf::from("/dev/fuse")),
                ];
                if positive_first {
                    targets.reverse();
                }
                assert_eq!(fuse_device_from_link_targets(targets), Some(true));
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn fuse_fixture_task(
        process_dir: &std::path::Path,
        tid: u32,
        birth: u64,
    ) -> std::path::PathBuf {
        let task = process_dir.join("task").join(tid.to_string());
        std::fs::create_dir_all(task.join("fd")).unwrap();
        let mut fields = vec!["0".to_string(); 22];
        fields[0] = "S".to_string();
        fields[1] = "1".to_string();
        fields[17] = "2".to_string();
        fields[19] = birth.to_string();
        std::fs::write(
            task.join("stat"),
            format!("{tid} (worker) {}\n", fields.join(" ")),
        )
        .unwrap();
        task
    }

    #[cfg(target_os = "linux")]
    fn fuse_fixture_budget() -> FuseInspectionBudget {
        FuseInspectionBudget {
            deadline: std::time::Instant::now() + Duration::from_secs(5),
            ..FuseInspectionBudget::default()
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fuse_inspection_finds_private_worker_devices_despite_incomplete_leader() {
        for target in ["/dev/fuse", "/dev/fuse (deleted)"] {
            for leader_available in [true, false] {
                let process = tempfile::tempdir().unwrap();
                let leader = fuse_fixture_task(process.path(), 42, 100);
                let worker = fuse_fixture_task(process.path(), 43, 101);
                std::os::unix::fs::symlink("/dev/null", leader.join("fd/0")).unwrap();
                // Distinct task tables model a worker that used unshare(CLONE_FILES).
                // The leader's harmless table must not hide the worker's device.
                assert_eq!(fuse_device_in_fd_table(&leader.join("fd")), Some(false));
                std::os::unix::fs::symlink(target, worker.join("fd/7")).unwrap();
                if !leader_available {
                    // An exited leader can retain a stat record while its fd table
                    // is unavailable. Positive worker evidence must still survive.
                    std::fs::rename(
                        leader.join("fd"),
                        process.path().join("retained-leader-fds"),
                    )
                    .unwrap();
                }
                assert_eq!(
                    holds_fuse_device_from(process.path(), 42, &mut fuse_fixture_budget(), || {},),
                    Some(true),
                    "{target}, leader_available={leader_available}"
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fuse_inspection_refuses_incomplete_task_or_descriptor_evidence() {
        for failure in [
            "missing_leader",
            "missing_worker_fds",
            "missing_worker_stat",
            "wrong_worker_identity",
            "oversized_worker_stat",
            "invalid_task_id",
            "zero_task_id",
            "invalid_descriptor_id",
            "unreadable_descriptor",
        ] {
            let process = tempfile::tempdir().unwrap();
            let leader = fuse_fixture_task(process.path(), 42, 100);
            let worker = fuse_fixture_task(process.path(), 43, 101);
            std::os::unix::fs::symlink("/dev/null", leader.join("fd/0")).unwrap();
            std::os::unix::fs::symlink("socket:[123]", worker.join("fd/0")).unwrap();
            assert_eq!(
                holds_fuse_device_from(process.path(), 42, &mut fuse_fixture_budget(), || {}),
                Some(false)
            );
            let mut pid = 42;
            match failure {
                "missing_leader" => pid = 41,
                "missing_worker_fds" => {
                    std::fs::rename(
                        worker.join("fd"),
                        process.path().join("retained-worker-fds"),
                    )
                    .unwrap();
                }
                "missing_worker_stat" => {
                    std::fs::rename(
                        worker.join("stat"),
                        process.path().join("retained-worker-stat"),
                    )
                    .unwrap();
                }
                "wrong_worker_identity" => {
                    let stat = std::fs::read_to_string(leader.join("stat")).unwrap();
                    std::fs::write(worker.join("stat"), stat).unwrap();
                }
                "oversized_worker_stat" => {
                    std::fs::write(worker.join("stat"), vec![b'0'; 16 * 1024 + 1]).unwrap();
                }
                "invalid_task_id" => {
                    std::fs::create_dir(process.path().join("task/043")).unwrap();
                }
                "zero_task_id" => {
                    std::fs::create_dir(process.path().join("task/0")).unwrap();
                }
                "invalid_descriptor_id" => {
                    std::os::unix::fs::symlink("/dev/null", worker.join("fd/01")).unwrap();
                }
                "unreadable_descriptor" => {
                    std::fs::write(worker.join("fd/1"), b"not a descriptor symlink").unwrap();
                }
                _ => unreachable!(),
            }
            assert_eq!(
                holds_fuse_device_from(process.path(), pid, &mut fuse_fixture_budget(), || {}),
                None,
                "{failure}"
            );
            // Incomplete evidence is never allowed to erase a known device.
            std::os::unix::fs::symlink("/dev/fuse", leader.join("fd/9")).unwrap();
            assert_eq!(
                holds_fuse_device_from(process.path(), pid, &mut fuse_fixture_budget(), || {}),
                Some(true),
                "{failure}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fuse_inspection_rechecks_task_identity_and_descriptor_churn() {
        for change in [
            "new_task",
            "exited_task",
            "reused_tid",
            "replaced_task_same_birth",
            "new_descriptor",
            "retargeted_descriptor",
            "new_fuse_descriptor",
        ] {
            let process = tempfile::tempdir().unwrap();
            let leader = fuse_fixture_task(process.path(), 42, 100);
            let worker = fuse_fixture_task(process.path(), 43, 101);
            std::os::unix::fs::symlink("/dev/null", leader.join("fd/0")).unwrap();
            std::os::unix::fs::symlink("socket:[123]", worker.join("fd/0")).unwrap();
            let result =
                holds_fuse_device_from(process.path(), 42, &mut fuse_fixture_budget(), || {
                    match change {
                        "new_task" => {
                            fuse_fixture_task(process.path(), 44, 102);
                        }
                        "exited_task" => {
                            std::fs::rename(&worker, process.path().join("retained-task")).unwrap();
                        }
                        "reused_tid" => {
                            fuse_fixture_task(process.path(), 43, 200);
                        }
                        "replaced_task_same_birth" => {
                            std::fs::rename(&worker, process.path().join("retained-task")).unwrap();
                            let replacement = fuse_fixture_task(process.path(), 43, 101);
                            std::os::unix::fs::symlink("socket:[123]", replacement.join("fd/0"))
                                .unwrap();
                        }
                        "new_descriptor" => {
                            std::os::unix::fs::symlink("/dev/null", worker.join("fd/9")).unwrap();
                        }
                        "retargeted_descriptor" => {
                            std::fs::rename(
                                worker.join("fd/0"),
                                process.path().join("retained-descriptor"),
                            )
                            .unwrap();
                            std::os::unix::fs::symlink("socket:[456]", worker.join("fd/0"))
                                .unwrap();
                        }
                        "new_fuse_descriptor" => {
                            std::os::unix::fs::symlink("/dev/fuse", worker.join("fd/9")).unwrap();
                        }
                        _ => unreachable!(),
                    }
                });
            assert_eq!(
                result,
                if change == "new_fuse_descriptor" {
                    Some(true)
                } else {
                    None
                },
                "{change}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fuse_inspection_work_budget_spans_tasks_and_both_passes() {
        let process = tempfile::tempdir().unwrap();
        for tid in [42, 43] {
            let task = fuse_fixture_task(process.path(), tid, 100);
            // Equal descriptor contents do not prove that tables are shared.
            std::os::unix::fs::symlink("/dev/null", task.join("fd/0")).unwrap();
        }
        // Each pass reads two task entries before and after two descriptors.
        // Both complete passes therefore consume exactly twelve entry credits.
        for credits in [0, 6, 11, 12] {
            let mut budget = fuse_fixture_budget();
            budget.remaining_entries = credits;
            assert_eq!(
                holds_fuse_device_from(process.path(), 42, &mut budget, || {}),
                if credits == 12 { Some(false) } else { None },
                "credits={credits}"
            );
        }
        let mut limited_tasks = fuse_fixture_budget();
        limited_tasks.max_tasks = 1;
        assert_eq!(
            holds_fuse_device_from(process.path(), 42, &mut limited_tasks, || {}),
            None
        );
        let mut expired = fuse_fixture_budget();
        expired.deadline = std::time::Instant::now();
        assert_eq!(
            holds_fuse_device_from(process.path(), 42, &mut expired, || {}),
            None
        );
        for pid in [0, u32::MAX] {
            assert_eq!(
                holds_fuse_device_from(process.path(), pid, &mut fuse_fixture_budget(), || {}),
                None
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fuse_mount_attribution_requires_exact_arguments_and_fuse_filesystem() {
        let mountinfo = concat!(
            "10 1 0:21 / /mnt/other rw - fuse.sshfs remote rw\n",
            "11 1 0:22 / /mnt/fs rw - ext4 /dev/sda rw\n",
            "12 1 0:23 / /mnt/fs-more rw - fuse.ffs frankenfs rw\n",
            "13 1 0:24 / /mnt/fuse\\040space rw - fuse.ffs frankenfs rw\n",
            "14 1 0:25 / /mnt/block rw - fuseblk disk rw\n",
            "15 1 0:26 / /mnt/option rw - fuse generic rw\n",
            "16 1 0:24 / /mnt/fuse\\040space rw - fuse.ffs frankenfs rw\n",
        );
        let mounts = fuse_mountpoints_from_inputs(
            mountinfo,
            b"ffs-cli\0mount\0/mnt/fs\0/mnt/fuse space\0/mnt/block\0--mountpoint=/mnt/option\0",
        );
        assert_eq!(mounts, vec!["/mnt/block", "/mnt/fuse space", "/mnt/option"]);
        assert!(fuse_mountpoints_from_inputs(mountinfo, b"ffs-cli\0mount\0").is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fuse_mount_attribution_decodes_procfs_escapes_and_ignores_malformed_rows() {
        assert_eq!(
            decode_mountinfo_path(br"/mnt/space\040tab\011line\012slash\134"),
            Some(b"/mnt/space tab\tline\nslash\\".to_vec())
        );
        for invalid in [br"/mnt/\".as_slice(), br"/mnt/\04", br"/mnt/\999"] {
            assert_eq!(decode_mountinfo_path(invalid), None);
        }
        assert!(fuse_mountpoints_from_inputs(
            "broken row\n1 2 3 - fuse foo rw\n1 2 3 / /mnt/\\999 rw - fuse foo rw\n",
            b"server\0/mnt/\\999\0"
        )
        .is_empty());
    }

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
            container_info: None,
        }
    }

    use super::super::cgroup::CgroupRole;

    fn default_filter() -> ProtectedFilter {
        ProtectedFilter::from_guardrails(&crate::config::policy::Guardrails::default()).unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn census_user_service_admission_requires_the_current_binding_and_preserves_invoker_protection()
    {
        let filter = ProtectedFilter::new(&[], &[], &[], &[])
            .unwrap()
            .with_builtin_protection(true);
        let mut proc = make_test_record(13245, 12345, "sleep", "sleep 60", "alice");
        // SAFETY: geteuid only reads the caller's credentials.
        proc.uid = unsafe { libc::geteuid() };
        let unit = "fixture-worker.service";
        let binding = crate::action::SystemdUserServiceBinding {
            target: pt_common::ProcessIdentity::full(
                proc.pid.0,
                proc.start_id.clone(),
                proc.uid,
                proc.pgid,
                proc.sid,
                pt_common::IdentityQuality::Full,
            ),
            control_group: format!(
                "/user.slice/user-{0}.slice/user@{0}.service/{unit}",
                proc.uid
            ),
            unit: unit.into(),
            invocation_id: "0123456789abcdef0123456789abcdef".into(),
        };
        let scan = |binding, invokers: &HashSet<u32>| {
            filter.filter_with_observations(
                std::slice::from_ref(&proc),
                invokers,
                |_| CgroupRole::UserService,
                |_| binding,
            )
        };
        let no_invokers = HashSet::new();
        assert_eq!(
            scan(None, &no_invokers).filtered[0].matched_field,
            MatchedField::SupervisedService
        );
        assert_eq!(scan(Some(&binding), &no_invokers).passed[0].pid, proc.pid);
        assert_eq!(
            scan(Some(&binding), &HashSet::from([proc.pid.0])).filtered[0].matched_field,
            MatchedField::InvokerChain
        );
        let stale = crate::action::SystemdUserServiceBinding {
            target: pt_common::ProcessIdentity {
                start_id: StartId::from_linux("another-boot", 1234567890, proc.pid.0),
                ..binding.target.clone()
            },
            ..binding.clone()
        };
        assert_eq!(
            scan(Some(&stale), &no_invokers).filtered[0].matched_field,
            MatchedField::SupervisedService
        );
    }

    #[test]
    fn supervisor_restart_only_waives_user_service_placement() {
        let guards = crate::config::policy::Guardrails {
            never_kill_pid: vec![1],
            ..Default::default()
        };
        let filter = ProtectedFilter::from_guardrails(&guards).unwrap();
        let ordinary = make_test_record(43210, 4000, "sleep", "sleep 600", "alice");
        assert_eq!(
            filter
                .is_protected_with_role(&ordinary, CgroupRole::UserService)
                .unwrap()
                .matched_field,
            MatchedField::SupervisedService
        );
        assert!(filter
            .is_protected_with_role_and_restart(&ordinary, CgroupRole::UserService, true)
            .is_none());
        for role in [CgroupRole::SystemService, CgroupRole::Container] {
            assert_eq!(
                filter
                    .is_protected_with_role_and_restart(&ordinary, role, true)
                    .unwrap()
                    .matched_field,
                MatchedField::SupervisedService
            );
        }
        for protected in [
            make_test_record(1, 0, "sleep", "sleep 600", "alice"),
            make_test_record(43210, 1, "sleep", "sleep 600", "alice"),
            make_test_record(43210, 4000, "sleep", "sleep 600", "root"),
            make_test_record(43210, 4000, "sshd", "/usr/sbin/sshd -D", "alice"),
        ] {
            assert!(
                filter
                    .is_protected_with_role_and_restart(&protected, CgroupRole::UserService, true)
                    .is_some(),
                "lost explicit or built-in protection for {protected:?}"
            );
        }
        let guards = crate::config::policy::Guardrails {
            protected_users: vec!["alice".to_string()],
            ..Default::default()
        };
        let explicit = ProtectedFilter::from_guardrails(&guards).unwrap();
        assert_eq!(
            explicit
                .is_protected_with_role_and_restart(&ordinary, CgroupRole::UserService, true)
                .unwrap()
                .matched_field,
            MatchedField::User
        );
    }

    /// One placement rule for the scan filter and the enforcer, with the platform
    /// explicit so the macOS branch is tested on Linux too.
    #[test]
    fn builtin_placement_by_platform_and_role() {
        use BuiltinPlacement::*;
        use CgroupRole::*;
        let server = ("alice", "python3", "python3 -m http.server 8000");
        let place = |macos, role, (user, comm, cmd): (&str, &str, &str)| {
            placement_on(macos, role, user, comm, cmd)
        };
        for macos in [false, true] {
            for role in [SystemService, UserService, Container] {
                assert_eq!(place(macos, role, server), SupervisedService, "{role:?}");
            }
            for role in [LoginSession, TransientScope] {
                assert_eq!(place(macos, role, server), UserWorkload, "{role:?}");
            }
        }
        // Linux without systemd placement: guardrails apply unchanged.
        assert_eq!(place(false, Unknown, server), Unplaced);
        assert_eq!(
            place(false, Unknown, ("root", "make", "make -j8")),
            Unplaced
        );
        // macOS: owner and executable decide.
        assert_eq!(place(true, Unknown, server), UserWorkload);
        assert!(matches!(
            place(true, Unknown, ("root", "make", "make -j8")),
            MacSystem(_)
        ));
        assert!(matches!(
            place(
                true,
                Unknown,
                ("alice", "Zed", "/Applications/Zed.app/Contents/MacOS/zed")
            ),
            MacSystem(_)
        ));
        assert!(matches!(
            place(
                true,
                Unknown,
                (
                    "alice",
                    "/usr/libexec/trustd",
                    "/usr/libexec/trustd --agent"
                )
            ),
            MacSystem(_)
        ));
        // Owner unknown: nothing vouches for it as a user workload.
        assert_eq!(
            place(true, Unknown, ("", "python3", "python3 x.py")),
            Unplaced
        );
    }

    #[test]
    fn macos_placement_protects_system_and_apps_but_not_user_workloads() {
        use MacPlacement::*;
        let system = [
            ("root", "/usr/sbin/cfprefsd", "/usr/sbin/cfprefsd daemon"),
            ("_windowserver", "WindowServer", "/System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer -daemon"),
            ("nobody", "x", "x"),
            ("alice", "/usr/libexec/trustd", "/usr/libexec/trustd --agent"),
            ("alice", "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"),
            ("alice", "Google Chrome Helper", "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper --type=renderer"),
            ("alice", "Zed", "/Applications/Zed.app/Contents/MacOS/zed"),
        ];
        for (user, comm, cmd) in system {
            assert!(
                matches!(macos_placement(user, comm, cmd), System(_)),
                "{user} {cmd}"
            );
        }
        let workloads = [
            ("alice", "python3", "python3 -m http.server 8000"),
            (
                "alice",
                "node",
                "/Users/alice/.nvm/versions/node/v22/bin/node server.js",
            ),
            ("alice", "sleep", "sleep 7777"),
            ("alice", "python3", "/usr/bin/python3 train.py"),
            (
                "alice",
                "com.microsoft.teams2.agent",
                "/Users/alice/Library/Application Support/x/com.microsoft.teams2.agent",
            ),
        ];
        for (user, comm, cmd) in workloads {
            assert_eq!(
                macos_placement(user, comm, cmd),
                UserWorkload,
                "{user} {cmd}"
            );
        }
    }

    /// On macOS a user's orphan (reparented to launchd, PID 1) is a candidate, while
    /// system, Apple and app-bundle processes stay protected.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_user_orphans_are_evaluated() {
        let filter = default_filter();
        let orphan = make_test_record(
            1 << 22,
            1,
            "python3",
            "python3 -m http.server 8000",
            "alice",
        );
        assert!(
            filter.is_protected(&orphan).is_none(),
            "user orphan must be evaluated"
        );
        let helper = make_test_record(
            (1 << 22) + 1,
            1,
            "Slack Helper",
            "/Applications/Slack.app/Contents/Frameworks/Slack Helper.app/Contents/MacOS/Slack Helper",
            "alice",
        );
        let m = filter.is_protected(&helper).expect("app helper protected");
        assert_eq!(m.pattern, "builtin.macos_system");
        let daemon = make_test_record((1 << 22) + 2, 1, "trustd", "/usr/libexec/trustd", "alice");
        assert!(filter.is_protected(&daemon).is_some());
    }

    /// Database / web servers are protected by name even under rewritten titles
    /// (vmi workers, 2026-09-24: "postgres: 18/main: io worker" was rated abandoned).
    #[test]
    fn builtin_protects_service_daemons_by_name() {
        let protected = [
            ("postgres", "postgres: 18/main: io worker 2"),
            (
                "postgres",
                "/usr/lib/postgresql/18/bin/postgres -D /var/lib/postgresql/18/main",
            ),
            ("nginx", "nginx: worker process"),
            (
                "nginx",
                "nginx: master process /usr/sbin/nginx -g daemon on;",
            ),
            ("redis-server", "/usr/bin/redis-server 127.0.0.1:6379"),
            ("mysqld", "/usr/sbin/mysqld"),
            ("mattermost", "/opt/mattermost/bin/mattermost"),
            ("php-fpm8.3", "php-fpm: pool www"),
            (
                "clickhouse-serv",
                "/usr/bin/clickhouse-server --config-file=/etc/x.xml",
            ),
        ];
        for (comm, cmd) in protected {
            assert!(is_service_daemon(comm, cmd), "{comm} / {cmd}");
        }
        let not_daemons = [
            ("python3", "python3 -m pytest tests/test_postgres.py"),
            ("psql", "psql -h localhost -U app"),
            ("node", "node scripts/nginx-config-gen.js"),
            ("cargo", "cargo run --bin redis-server-mock"),
        ];
        for (comm, cmd) in not_daemons {
            assert!(!is_service_daemon(comm, cmd), "{comm} / {cmd}");
        }
    }

    #[test]
    fn builtin_protects_coordination_servers_and_monitor_children() {
        for cmd in [
            "/home/ubuntu/mcp_agent_mail/am",
            "am serve",
            "/opt/am serve-http --port 8765",
            "mcp-agent-mail serve",
            "/home/ubuntu/.local/bin/rchd",
            "rchd --foreground",
            "ntm internal-monitor frankensim",
        ] {
            assert_eq!(
                builtin_protection_match("daemon", cmd).map(|(rule, _)| rule),
                Some("builtin.agent_coordination"),
                "{cmd}"
            );
            assert_eq!(
                service_ancestor_with(
                    300,
                    |pid| (pid == 300).then_some(200),
                    |pid| (pid == 200).then(|| ("daemon".to_string(), cmd.to_string()))
                ),
                Some((200, "daemon".to_string())),
                "child of {cmd}"
            );
        }
        for cmd in [
            "am send alice",
            "am inbox",
            "amp serve",
            "am serve-other",
            "ntm attach frankensim",
            "ntm spawn frankensim",
            "ntm internal-monitor-fake",
            "bash -c 'am serve-http'",
            "pytest test_mcp_agent_mail.py",
            "rg rchd",
            "rchdoc serve",
        ] {
            assert!(!is_service_daemon("am", cmd), "{cmd}");
        }
        // A mux hosts workloads; its children must not inherit daemon protection.
        assert!(!is_service_daemon("tmux: server", "tmux new -d"));
    }

    /// Workers and plugins inherit protection from their server by parent identity,
    /// whatever they call themselves; unrelated processes do not.
    #[test]
    fn service_children_are_protected_by_parent_identity() {
        // PIDs above Linux's pid_max (2^22) never exist, so no live cgroup role leaks in;
        // the unrelated tree hangs off a non-init parent (PPID 1 is protected by default).
        const B: u32 = 1 << 22;
        let scan_result = ScanResult {
            processes: vec![
                make_test_record(
                    B + 100,
                    1,
                    "mattermost",
                    "/opt/mattermost/bin/mattermost",
                    "mm",
                ),
                make_test_record(
                    B + 101,
                    B + 100,
                    "plugin-linux-am",
                    "plugins/com.mattermost.calls/server/dist/plugin-linux-amd64",
                    "mm",
                ),
                make_test_record(
                    B + 102,
                    B + 101,
                    "ffmpeg",
                    "ffmpeg -i pipe:0 out.webm",
                    "mm",
                ),
                make_test_record(B + 200, B + 999, "sleep", "sleep 100", "mm"),
                make_test_record(B + 201, B + 200, "sleep", "sleep 5", "mm"),
            ],
            metadata: super::super::types::ScanMetadata {
                scan_type: "quick".to_string(),
                platform: "linux".to_string(),
                boot_id: None,
                started_at: "2026-09-24T12:00:00Z".to_string(),
                duration_ms: 1,
                process_count: 5,
                warnings: vec![],
            },
        };
        let result = default_filter().filter_scan_result(&scan_result);
        let passed: Vec<u32> = result.passed.iter().map(|p| p.pid.0).collect();
        assert_eq!(passed, vec![B + 200, B + 201]);
        let child = result
            .filtered
            .iter()
            .find(|m| m.pid == B + 102)
            .expect("grandchild filtered");
        assert_eq!(child.pattern, "builtin.service_child");
        let notes = child.notes.as_deref().unwrap();
        assert!(
            notes.contains(&format!("mattermost (pid {})", B + 100)),
            "{notes}"
        );
    }

    #[test]
    fn service_protection_traverses_deep_trees_and_terminates_on_cycles() {
        let mut processes = vec![make_test_record(100, 1, "postgres", "postgres -D /db", "u")];
        for pid in 101..=230 {
            processes.push(make_test_record(pid, pid - 1, "worker", "worker", "u"));
        }
        // A nested service is the nearest explanation for its own workers.
        processes.push(make_test_record(231, 230, "nginx", "nginx", "u"));
        processes.push(make_test_record(232, 231, "worker", "worker", "u"));
        processes.push(make_test_record(300, 301, "worker", "worker", "u"));
        processes.push(make_test_record(301, 300, "worker", "worker", "u"));
        processes.reverse();
        let result = default_filter().filter_with_observations(
            &processes,
            &HashSet::new(),
            |_| super::super::cgroup::CgroupRole::Unknown,
            |_| None,
        );
        for (leaf, daemon) in [(230, "postgres (pid 100)"), (232, "nginx (pid 231)")] {
            let protected = result.filtered.iter().find(|m| m.pid == leaf).unwrap();
            assert_eq!(protected.pattern, "builtin.service_child");
            assert!(protected.notes.as_deref().unwrap().contains(daemon));
        }
        assert!(result.passed.iter().any(|p| p.pid.0 == 300));
        // Apply observes parent IDs and command identities live through these
        // callbacks, without the scan cache. Both paths must agree.
        let by_pid: HashMap<_, _> = processes.iter().map(|p| (p.pid.0, p)).collect();
        for (pid, expected) in [(230, Some(100)), (232, Some(231)), (300, None)] {
            let live = service_ancestor_with(
                pid,
                |p| Some(by_pid.get(&p)?.ppid.0),
                |p| {
                    let record = by_pid.get(&p)?;
                    Some((record.comm.clone(), record.cmd.clone()))
                },
            );
            assert_eq!(live.map(|(p, _)| p), expected);
            assert_eq!(service_ancestor(pid, &by_pid).map(|(p, _)| p), expected);
        }
    }

    /// Every case here was rated P(abandoned) ~ 1.0 on the 2026-09-24 fleet scan.
    #[test]
    fn builtin_protects_live_infrastructure_from_fleet() {
        let cases = [
            ("frankenterm-mux", "/home/ubuntu/.local/bin/frankenterm-mux-server --daemonize=false --config-file=/home/ubuntu/.config/frankenterm/frankenterm.lua"),
            ("wezterm-mux-ser", "/usr/bin/wezterm-mux-server --pid-file-fd 10"),
            ("tmux: server", "/usr/bin/tmux new-session -d -s frankentorch -c /data/projects/frankentorch"),
            ("tmux: client", "tmux attach -t main"),
            ("ssh", "ssh -E /home/ubuntu/.ssh/rch/.ssh-connectionUXind1/log -S /home/ubuntu/.ssh/rch/.ssh-connectionUXind1/master -M -f -N vmi1149989"),
            ("ssh", "ssh -o ControlMaster=auto -o ControlPath=/tmp/cm-%r@%h ts2"),
            // ControlMaster from ssh_config: argv carries no flag, only OpenSSH's title.
            ("ssh", "ssh: /home/ubuntu/.ssh/sockets/ubuntu@ts2-22 [mux]"),
            ("sshd-session", "sshd-session: ubuntu@notty"),
            ("(sd-pam)", "(sd-pam)"),
            ("systemd", "/usr/lib/systemd/systemd --user"),
            ("zsh", "-zsh"),
            ("zsh", "/usr/bin/zsh"),
            ("bash", "bash --login"),
            ("login", "login -- ubuntu"),
            ("nc", "nc -U /run/user/1000/frankenterm/sock"),
            // A Mac's terminal remote domain (mac-mini-max, 16 of these, ppid 1, 30 h old).
            ("ssh", "ssh -i /Users/u/.ssh/key -o ConnectTimeout=10 -o BatchMode=yes -o ServerAliveInterval=30 u@host nc -U /run/user/1000/frankenterm/sock"),
            ("ssh", "ssh -T host wezterm cli proxy"),
        ];
        let filter = default_filter();
        for (comm, cmd) in cases {
            let rec = make_test_record(4242, 3000, comm, cmd, "ubuntu");
            let m = filter
                .is_protected_with_role(&rec, CgroupRole::TransientScope)
                .unwrap_or_else(|| panic!("expected builtin protection for {cmd:?}"));
            assert_eq!(m.matched_field, MatchedField::Builtin, "{cmd}");
        }
    }

    /// Dashboards and session hosts from the fleet (foot/cage kiosk, htop) and
    /// terminal emulators are someone's screen.
    #[test]
    fn builtin_protects_session_hosts_and_monitors() {
        let filter = default_filter();
        for (comm, cmd) in [
            ("foot", "foot --server"),
            ("cage", "cage -- foot htop"),
            ("htop", "htop"),
            ("btop", "/usr/bin/btop"),
            ("kitty", "/usr/bin/kitty"),
            ("Xwayland", "/usr/bin/Xwayland :0 -rootless"),
            ("sway", "sway"),
        ] {
            let rec = make_test_record(4242, 3000, comm, cmd, "ubuntu");
            let m = filter
                .is_protected_with_role(&rec, CgroupRole::TransientScope)
                .unwrap_or_else(|| panic!("{cmd:?} must be protected"));
            assert_eq!(m.pattern, "builtin.session_host", "{cmd:?}");
        }
    }

    /// Display-manager session helpers live in the login session's scope (sddm-helper
    /// runs as root in session-1.scope) and end the desktop when killed (GH #14).
    #[test]
    fn builtin_protects_display_manager_session_helpers() {
        let filter = default_filter();
        for (comm, cmd, user) in [
            (
                "sddm-helper",
                "/usr/lib/sddm/sddm-helper --socket /tmp/sddm-auth-1 --id 1 --start uwsm start -- hyprland.desktop --user alice --autologin",
                "root",
            ),
            (
                "gdm-session-wor",
                "gdm-session-worker [pam/gdm-password]",
                "root",
            ),
            (
                "gdm-wayland-ses",
                "/usr/libexec/gdm-wayland-session env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu",
                "alice",
            ),
            ("lightdm", "lightdm --session-child 13 20", "root"),
            (
                "gnome-session-b",
                "/usr/libexec/gnome-session-binary --session=ubuntu",
                "alice",
            ),
            ("python3", "/usr/bin/python3 /usr/bin/uwsm start -- hyprland.desktop", "alice"),
            ("ksmserver", "/usr/bin/ksmserver", "alice"),
        ] {
            let rec = make_test_record(4242, 3000, comm, cmd, user);
            let m = filter
                .is_protected_with_role(&rec, CgroupRole::LoginSession)
                .unwrap_or_else(|| panic!("{cmd:?} must be protected"));
            assert_eq!(m.pattern, "builtin.display_manager_session", "{cmd:?}");
        }
        // Mentioning a session tool is not being one.
        for (comm, cmd) in [
            ("uwsm", "uwsm app -- slack"),
            ("rg", "rg sddm-helper /var/log"),
        ] {
            let rec = make_test_record(4243, 3000, comm, cmd, "alice");
            assert!(
                filter
                    .is_protected_with_role(&rec, CgroupRole::TransientScope)
                    .is_none(),
                "{cmd:?} must stay a candidate"
            );
        }
    }

    #[test]
    fn builtin_does_not_protect_real_candidates() {
        let cases = [
            ("zsh", "/usr/bin/zsh -c source /home/ubuntu/.claude/shell-snapshots/snapshot-zsh-1.sh && cargo test"),
            ("sh", "sh -c cargo test -p hfdt-cli date_filter"),
            ("rch", "rch exec -- cargo test -p hfdt-cli date_filter"),
            ("cargo", "/root/.rustup/toolchains/nightly/bin/cargo test --locked --all-targets"),
            ("sleep", "sleep 14400"),
            ("ssh", "ssh ts2 uptime"),
            ("ssh", "ssh ts2 tmux ls"),
            ("ssh", "ssh ts2 nc -z db 5432"),
            ("ssh", "ssh ts2 echo [mux]"),
            ("node", "node /data/projects/app/node_modules/.bin/next dev"),
            ("bun", "bun test"),
            ("Xvfb", "Xvfb :99 -screen 0 1280x1024x24"),
            ("topgrade", "topgrade --yes"),
        ];
        let filter = default_filter();
        for (comm, cmd) in cases {
            let rec = make_test_record(4242, 3000, comm, cmd, "ubuntu");
            assert!(
                filter
                    .is_protected_with_role(&rec, CgroupRole::TransientScope)
                    .is_none(),
                "{cmd:?} must stay a candidate"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn tty_idle_seconds_reads_last_io_time() {
        let dir = tempfile::tempdir().unwrap();
        let dev = dir.path().join("pts-test");
        let f = std::fs::File::create(&dev).unwrap();
        let past = std::time::SystemTime::now() - std::time::Duration::from_secs(600);
        f.set_times(
            std::fs::FileTimes::new()
                .set_accessed(past)
                .set_modified(past),
        )
        .unwrap();
        let idle = tty_idle_seconds(dev.to_str().unwrap()).expect("stat");
        assert!((595..=660).contains(&idle), "idle {idle}");
        assert_eq!(tty_idle_seconds("/nonexistent/pts/999"), None);
    }

    #[test]
    fn agent_kind_names_the_agent() {
        let cases = [
            ("claude --dangerously-skip-permissions", Some("claude")),
            (
                "/home/u/.local/share/claude/versions/2.1.280 --session-id 1",
                Some("claude"),
            ),
            (
                "node /usr/lib/node_modules/@openai/codex/bin/codex.js",
                Some("codex"),
            ),
            (
                "zsh -ic 'cd /data/campus; cod --no-alt-screen'",
                Some("codex"),
            ),
            ("agy --yolo", Some("gemini")),
            ("cursor-agent -p fix", Some("cursor")),
            ("rg codex src/", None),
            ("cargo test -p campus", None),
        ];
        for (cmd, want) in cases {
            assert_eq!(agent_kind(cmd), want, "{cmd:?}");
        }
    }

    #[test]
    fn pi_agent_entrypoints_match_without_argument_or_package_collisions() {
        for cmd in [
            "pi",
            "pi --continue",
            "/home/ubuntu/.local/bin/pi --provider anthropic",
            "/data/projects/pi_agent_rust/target/release/pi --mode rpc",
            // Kind comes from the entrypoint, never a model or prompt argument.
            "pi --model claude --print review-codex",
            "node /usr/lib/node_modules/@mariozechner/pi-coding-agent/dist/cli.js",
            "/usr/bin/nodejs /home/codex/node_modules/@mariozechner/pi-coding-agent/dist/cli.js --continue",
            "/home/u/.bun/bin/bun /home/u/.bun/install/global/node_modules/@mariozechner/pi-coding-agent/dist/cli.js",
            "node @mariozechner/pi-coding-agent/dist/cli.js --mode rpc",
        ] {
            assert_eq!(agent_kind(cmd), Some("pi"), "{cmd}");
            let matched = builtin_force_review_match(cmd).expect("Pi requires review");
            assert_eq!(matched.0, "builtin.agent_cli", "{cmd}");
            assert!(builtin_protection_match("pi", cmd).is_none(), "{cmd}");
        }
        for cmd in [
            "pip install numpy",
            "pihole-FTL",
            "piquant --continue",
            "rg pi src/",
            "cat /tmp/pi",
            "python3 -c 'import math; print(math.pi)'",
            "rsync source host:/data/pi",
            "bash -c 'printf %s pi'",
            "node /tmp/server.js",
            "node /tmp/server.js /usr/lib/node_modules/@mariozechner/pi-coding-agent/dist/cli.js",
            "node /usr/lib/node_modules/@mariozechner/pi-coding-agent-extra/dist/cli.js",
            "node /usr/lib/node_modules/@mariozechner/pi-coding-agent/dist/cli.js.map",
            "rg @mariozechner/pi-coding-agent/dist/cli.js src/",
            "bun test @mariozechner/pi-coding-agent/dist/cli.js",
        ] {
            assert_eq!(agent_kind(cmd), None, "{cmd}");
            assert!(builtin_force_review_match(cmd).is_none(), "{cmd}");
        }
    }

    #[test]
    fn agent_clis_are_force_review() {
        for cmd in [
            "claude --dangerously-skip-permissions --effort xhigh",
            "/home/ubuntu/.local/bin/claude --dangerously-skip-permissions",
            "/home/ubuntu/.local/share/claude/versions/2.1.280 --session-id 2425 --fork-session",
            "/home/ubuntu/.local/bin/agy-real --model Gemini 3.8 Flash (High) --dangerously-skip-permissions",
            "/home/ubuntu/.bun/install/global/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex",
            "codex --yolo",
            // Seen on css (2026-09-25): an agent launched from a shell -c script via an
            // installer wrapper `cod` (which execs codex); rated "pause" before.
            r#"/usr/bin/zsh -ic path=("$RUN_DIR/bin" $path); cod --no-alt-screen -C "$RUN_DIR/work" "$@" mtdt-codex"#,
            "cod --no-alt-screen",
            "bash -lc 'cd /repo && claude -p fix-tests'",
        ] {
            assert!(builtin_force_review_match(cmd).is_some(), "{cmd}");
        }
        for cmd in [
            "cargo test -p claude_parser",
            "vim claude.md",
            "rg codex src/",
            "bash -c 'rg codex src/'",
            "sh -c 'make codec'",
        ] {
            assert!(builtin_force_review_match(cmd).is_none(), "{cmd}");
        }
    }

    #[test]
    fn session_workloads_exempt_from_root_and_ppid1_protection() {
        let filter = default_filter();
        // Root build started over SSH on a worker, reparented to PID 1.
        let rec = make_test_record(
            294280,
            1,
            "cargo",
            "/root/.rustup/toolchains/nightly/bin/cargo test --locked",
            "root",
        );
        assert!(filter
            .is_protected_with_role(&rec, CgroupRole::LoginSession)
            .is_none());
        // Without a known session placement the conservative rules still apply.
        let m = filter
            .is_protected_with_role(&rec, CgroupRole::Unknown)
            .expect("protected without cgroup evidence");
        // (On macOS root is the launchd system domain: protected by that built-in rule.)
        assert!(
            matches!(m.matched_field, MatchedField::Ppid | MatchedField::User)
                || (cfg!(target_os = "macos") && m.matched_field == MatchedField::Builtin),
            "{m:?}"
        );
        // System services are protected regardless of user (a unit the name rules
        // do not know, so only its cgroup placement protects it).
        let app = make_test_record(
            4131051,
            4131046,
            "gunicorn",
            "/srv/app/.venv/bin/gunicorn app:app --workers 4",
            "www-data",
        );
        assert_eq!(
            filter
                .is_protected_with_role(&app, CgroupRole::SystemService)
                .unwrap()
                .matched_field,
            MatchedField::SupervisedService
        );
    }

    #[test]
    fn explicitly_protected_users_are_honored_even_in_sessions() {
        let g = crate::config::policy::Guardrails {
            protected_users: vec!["root".to_string(), "alice".to_string()],
            ..Default::default()
        };
        let filter = ProtectedFilter::from_guardrails(&g).unwrap();
        let alice = make_test_record(5000, 4000, "cargo", "cargo test", "alice");
        let m = filter
            .is_protected_with_role(&alice, CgroupRole::LoginSession)
            .expect("operator-listed user stays protected");
        assert_eq!(m.matched_field, MatchedField::User);
        let root = make_test_record(5001, 4000, "cargo", "cargo test", "root");
        assert!(filter
            .is_protected_with_role(&root, CgroupRole::LoginSession)
            .is_none());
    }

    #[test]
    fn builtin_disabled_keeps_legacy_behavior() {
        let g = crate::config::policy::Guardrails {
            builtin_protection: false,
            ..Default::default()
        };
        let filter = ProtectedFilter::from_guardrails(&g).unwrap();
        let rec = make_test_record(4242, 3000, "tmux: server", "tmux new-session -d", "ubuntu");
        assert!(filter
            .is_protected_with_role(&rec, CgroupRole::SystemService)
            .is_none());
        let root = make_test_record(4243, 1, "cargo", "cargo test", "root");
        assert!(filter
            .is_protected_with_role(&root, CgroupRole::LoginSession)
            .is_some());
    }

    #[test]
    fn invoker_chain_protects_pt_and_its_callers() {
        let me = std::process::id();
        let records = vec![
            make_test_record(me, 900_001, "pt-core", "pt-core agent plan", "ubuntu"),
            make_test_record(900_001, 900_002, "zsh", "zsh -c pt agent plan", "ubuntu"),
            make_test_record(
                900_002,
                1,
                "claude",
                "claude --dangerously-skip-permissions",
                "ubuntu",
            ),
            make_test_record(900_003, 900_002, "sleep", "sleep 100", "ubuntu"),
        ];
        let chain = invoker_chain_pids(&records);
        assert!(chain.contains(&me) && chain.contains(&900_001) && chain.contains(&900_002));
        assert!(!chain.contains(&900_003), "siblings are not protected");
    }

    #[test]
    fn truncate_cmd_is_utf8_safe() {
        let cmd = "é".repeat(100);
        let t = truncate_cmd(&cmd, 80);
        assert!(t.ends_with("..."));
        assert!(t.len() <= 80);
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
