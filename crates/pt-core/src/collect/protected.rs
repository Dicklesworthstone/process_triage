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

        if self.builtin {
            if let Some((name, notes)) = builtin_protection_match(&record.comm, &record.cmd) {
                return Some(make(
                    MatchedField::Builtin,
                    name.to_string(),
                    Some(notes.to_string()),
                ));
            }
            if role.is_supervised_service() {
                return Some(make(
                    MatchedField::SupervisedService,
                    format!("cgroup:{role:?}"),
                    Some(
                        "supervised by systemd or a container runtime; stop the unit instead"
                            .to_string(),
                    ),
                ));
            }
        }
        let mut session_workload = self.builtin && role.is_user_workload();
        // macOS has no cgroups (the role is always Unknown there): classify by owner
        // and executable instead.
        if self.builtin && cfg!(target_os = "macos") && role == super::cgroup::CgroupRole::Unknown {
            match macos_placement(&record.user, &record.comm, &record.cmd) {
                MacPlacement::System(notes) => {
                    return Some(make(
                        MatchedField::Builtin,
                        "builtin.macos_system".to_string(),
                        Some(notes.to_string()),
                    ));
                }
                MacPlacement::UserWorkload => session_workload = true,
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
        let total_before = scan_result.processes.len();
        let mut passed = Vec::with_capacity(total_before);
        let mut filtered = Vec::new();
        let invoker_chain = if self.builtin {
            invoker_chain_pids(&scan_result.processes)
        } else {
            HashSet::new()
        };
        let by_pid: std::collections::HashMap<u32, &ProcessRecord> =
            scan_result.processes.iter().map(|p| (p.pid.0, p)).collect();

        for record in &scan_result.processes {
            let protection = if invoker_chain.contains(&record.pid.0) {
                Some(ProtectedMatch {
                    pid: record.pid.0,
                    comm: record.comm.clone(),
                    cmd_truncated: truncate_cmd(&record.cmd, 80),
                    matched_field: MatchedField::InvokerChain,
                    pattern: "builtin.invoker_chain".to_string(),
                    notes: Some("pt itself or one of the processes that invoked it".to_string()),
                })
            } else {
                self.is_protected(record).or_else(|| {
                    let (daemon_pid, daemon) = self
                        .builtin
                        .then(|| service_ancestor(record.pid.0, &by_pid))??;
                    Some(ProtectedMatch {
                        pid: record.pid.0,
                        comm: record.comm.clone(),
                        cmd_truncated: truncate_cmd(&record.cmd, 80),
                        matched_field: MatchedField::Builtin,
                        pattern: "builtin.service_child".to_string(),
                        notes: Some(format!(
                            "worker/plugin of service {daemon} (pid {daemon_pid})"
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
            "builtin.ssh_control_master",
            Cmd,
            r"^(\S*/)?ssh\s(.*\s)?(-[1246AaCfGgKkMNnqsTtVvXxYy]*M[1246AaCfGgKkMNnqsTtVvXxYy]*|-oControlMaster=\S+|ControlMaster=(yes|auto|autoask|ask))(\s|$)",
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
            "AI agent CLI session: may be mid-task; kill only after manual review",
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

/// Built-in force-review match (agent CLIs), if any applies.
pub fn builtin_force_review_match(cmd: &str) -> Option<(&'static str, &'static str)> {
    // Agent CLIs are identified by their command line; comm is too short/ambiguous.
    builtin_match(&BUILTIN_FORCE_REVIEW, "", cmd)
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

/// Name of the built-in rule for database / web / message servers.
pub const SERVICE_DAEMON_RULE: &str = "builtin.service_daemon";

/// Maximum ancestor depth walked for parent-identity protection.
const MAX_ANCESTOR_DEPTH: usize = 64;

/// Whether a process is itself a database / web / message server.
pub fn is_service_daemon(comm: &str, cmd: &str) -> bool {
    builtin_protection_match(comm, cmd).is_some_and(|(rule, _)| rule == SERVICE_DAEMON_RULE)
}

/// Nearest ancestor of `pid` that is a service daemon (`(pid, comm)`), walking the
/// parent chain with `parent_of`/`identity_of`. Workers and plugins inherit their
/// server's protection by parent identity, whatever title they give themselves.
fn service_ancestor_with(
    pid: u32,
    parent_of: impl Fn(u32) -> Option<u32>,
    identity_of: impl Fn(u32) -> Option<(String, String)>,
) -> Option<(u32, String)> {
    let mut current = pid;
    for _ in 0..MAX_ANCESTOR_DEPTH {
        let parent = parent_of(current)?;
        if parent <= 1 || parent == current {
            return None;
        }
        if let Some((comm, cmd)) = identity_of(parent) {
            if is_service_daemon(&comm, &cmd) {
                return Some((parent, comm));
            }
        }
        current = parent;
    }
    None
}

/// [`service_ancestor_with`] over a scan (no extra syscalls).
pub fn service_ancestor(
    pid: u32,
    processes: &std::collections::HashMap<u32, &ProcessRecord>,
) -> Option<(u32, String)> {
    service_ancestor_with(
        pid,
        |p| processes.get(&p).map(|r| r.ppid.0),
        |p| processes.get(&p).map(|r| (r.comm.clone(), r.cmd.clone())),
    )
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
