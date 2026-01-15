//! Nohup and disown background process detection.
//!
//! Detects processes started with nohup or disown that are intentionally
//! backgrounded and may be orphaned when the shell exits.

use super::types::{EvidenceType, SupervisionEvidence};
use std::fs;
use std::path::Path;
use thiserror::Error;

/// Errors from nohup detection.
#[derive(Debug, Error)]
pub enum NohupError {
    #[error("I/O error reading /proc/{pid}: {source}")]
    IoError {
        pid: u32,
        #[source]
        source: std::io::Error,
    },

    #[error("Process {0} not found")]
    ProcessNotFound(u32),

    #[error("Parse error for /proc/{pid}/status: {message}")]
    ParseError { pid: u32, message: String },
}

/// Bitmask position for SIGHUP (signal 1) in the signal mask.
/// Signal masks in /proc/<pid>/status use a hex bitmask where bit N represents signal N+1.
const SIGHUP_MASK: u64 = 1 << 0; // SIGHUP is signal 1, so bit 0

/// Result of nohup/disown detection.
#[derive(Debug, Clone)]
pub struct NohupResult {
    /// Whether the process appears to be nohup'd or disown'd.
    pub is_background: bool,
    /// Whether SIGHUP is ignored.
    pub ignores_sighup: bool,
    /// Whether the process appears orphaned (PPID=1).
    pub is_orphaned: bool,
    /// Whether nohup was detected in command line.
    pub has_nohup_cmd: bool,
    /// Whether output redirected to nohup.out.
    pub has_nohup_output: bool,
    /// Activity level of nohup.out file (if any).
    pub nohup_output_activity: Option<NohupOutputActivity>,
    /// Evidence collected during detection.
    pub evidence: Vec<SupervisionEvidence>,
    /// Overall confidence score (0.0-1.0).
    pub confidence: f64,
    /// Inferred intent: intentional or accidental background.
    pub inferred_intent: BackgroundIntent,
}

/// Activity status of nohup.out file.
#[derive(Debug, Clone, PartialEq)]
pub enum NohupOutputActivity {
    /// File is being actively written to.
    Active,
    /// File exists but hasn't been modified recently.
    Stale,
    /// No output file found.
    None,
}

/// Inferred intent of the backgrounding.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BackgroundIntent {
    /// Process appears intentionally backgrounded.
    Intentional,
    /// Process appears forgotten or abandoned.
    Forgotten,
    /// Cannot determine intent.
    Unknown,
}

impl NohupResult {
    /// Create a result indicating no background detection.
    pub fn not_background() -> Self {
        Self {
            is_background: false,
            ignores_sighup: false,
            is_orphaned: false,
            has_nohup_cmd: false,
            has_nohup_output: false,
            nohup_output_activity: None,
            evidence: vec![],
            confidence: 0.0,
            inferred_intent: BackgroundIntent::Unknown,
        }
    }
}

/// Signal mask information from /proc/<pid>/status.
#[derive(Debug, Clone, Default)]
pub struct SignalMask {
    /// Signals being blocked (SigBlk).
    pub blocked: u64,
    /// Signals being ignored (SigIgn).
    pub ignored: u64,
    /// Signals being caught (SigCgt).
    pub caught: u64,
    /// Pending signals (SigPnd).
    pub pending: u64,
}

impl SignalMask {
    /// Check if SIGHUP is ignored.
    pub fn ignores_sighup(&self) -> bool {
        (self.ignored & SIGHUP_MASK) != 0
    }

    /// Check if SIGHUP is caught (has a handler).
    pub fn catches_sighup(&self) -> bool {
        (self.caught & SIGHUP_MASK) != 0
    }
}

/// Read signal mask from /proc/<pid>/status.
#[cfg(target_os = "linux")]
pub fn read_signal_mask(pid: u32) -> Result<SignalMask, NohupError> {
    let path = format!("/proc/{}/status", pid);
    let content = fs::read_to_string(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            NohupError::ProcessNotFound(pid)
        } else {
            NohupError::IoError { pid, source: e }
        }
    })?;

    parse_signal_mask(&content, pid)
}

#[cfg(not(target_os = "linux"))]
pub fn read_signal_mask(_pid: u32) -> Result<SignalMask, NohupError> {
    Ok(SignalMask::default())
}

/// Parse signal mask from /proc/<pid>/status content.
fn parse_signal_mask(content: &str, pid: u32) -> Result<SignalMask, NohupError> {
    let mut mask = SignalMask::default();

    for line in content.lines() {
        let (key, value) = match line.split_once(':') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };

        let parse_hex = |s: &str| -> Result<u64, NohupError> {
            u64::from_str_radix(s, 16).map_err(|_| NohupError::ParseError {
                pid,
                message: format!("invalid hex signal mask: {}", s),
            })
        };

        match key {
            "SigBlk" => mask.blocked = parse_hex(value)?,
            "SigIgn" => mask.ignored = parse_hex(value)?,
            "SigCgt" => mask.caught = parse_hex(value)?,
            "SigPnd" => mask.pending = parse_hex(value)?,
            _ => {}
        }
    }

    Ok(mask)
}

/// Check if SIGHUP is ignored by a process.
pub fn check_signal_mask(pid: u32) -> Result<bool, NohupError> {
    let mask = read_signal_mask(pid)?;
    Ok(mask.ignores_sighup())
}

/// Read PPID from /proc/<pid>/stat.
#[cfg(target_os = "linux")]
pub fn read_ppid(pid: u32) -> Result<u32, NohupError> {
    let path = format!("/proc/{}/stat", pid);
    let content = fs::read_to_string(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            NohupError::ProcessNotFound(pid)
        } else {
            NohupError::IoError { pid, source: e }
        }
    })?;

    // Format: pid (comm) state ppid ...
    // Find last ')' to handle comm with spaces/parens
    let close_paren = content.rfind(')').ok_or_else(|| NohupError::ParseError {
        pid,
        message: "missing ')' in stat".to_string(),
    })?;

    let rest = &content[close_paren + 2..]; // Skip ") "
    let fields: Vec<&str> = rest.split_whitespace().collect();

    if fields.len() < 2 {
        return Err(NohupError::ParseError {
            pid,
            message: "too few fields in stat".to_string(),
        });
    }

    // Field 1 (after state) is ppid
    fields[1]
        .parse()
        .map_err(|_| NohupError::ParseError {
            pid,
            message: format!("invalid ppid: {}", fields[1]),
        })
}

#[cfg(not(target_os = "linux"))]
pub fn read_ppid(_pid: u32) -> Result<u32, NohupError> {
    Ok(0)
}

/// Read command line from /proc/<pid>/cmdline.
#[cfg(target_os = "linux")]
fn read_cmdline(pid: u32) -> Result<String, NohupError> {
    let path = format!("/proc/{}/cmdline", pid);
    let content = fs::read(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            NohupError::ProcessNotFound(pid)
        } else {
            NohupError::IoError { pid, source: e }
        }
    })?;

    // cmdline uses NUL as separator
    let cmdline = content
        .split(|&b| b == 0)
        .filter_map(|s| std::str::from_utf8(s).ok())
        .collect::<Vec<_>>()
        .join(" ");

    Ok(cmdline.trim().to_string())
}

#[cfg(not(target_os = "linux"))]
fn read_cmdline(_pid: u32) -> Result<String, NohupError> {
    Ok(String::new())
}

/// Check for nohup in command line.
pub fn detect_nohup_command(pid: u32) -> Result<bool, NohupError> {
    let cmdline = read_cmdline(pid)?;

    // Check for nohup prefix or as first argument
    let lower = cmdline.to_lowercase();
    Ok(lower.starts_with("nohup ")
        || lower.contains("/nohup ")
        || cmdline.split_whitespace().any(|arg| arg == "nohup"))
}

/// File descriptor information for detecting output redirections.
#[derive(Debug, Clone, Default)]
pub struct FdInfo {
    /// Path of stdout (fd 1).
    pub stdout_path: Option<String>,
    /// Path of stderr (fd 2).
    pub stderr_path: Option<String>,
    /// Whether stdout is /dev/null.
    pub stdout_null: bool,
    /// Whether stderr is /dev/null.
    pub stderr_null: bool,
    /// Whether output goes to nohup.out.
    pub nohup_output: bool,
}

/// Read file descriptor targets for stdout/stderr.
#[cfg(target_os = "linux")]
pub fn read_fd_info(pid: u32) -> Result<FdInfo, NohupError> {
    let fd_dir = format!("/proc/{}/fd", pid);

    if !Path::new(&fd_dir).exists() {
        return Err(NohupError::ProcessNotFound(pid));
    }

    let mut info = FdInfo::default();

    // Read stdout (fd 1)
    if let Ok(target) = fs::read_link(format!("{}/1", fd_dir)) {
        let path = target.to_string_lossy().to_string();
        info.stdout_null = path == "/dev/null";
        info.nohup_output = path.ends_with("/nohup.out") || path == "nohup.out";
        info.stdout_path = Some(path);
    }

    // Read stderr (fd 2)
    if let Ok(target) = fs::read_link(format!("{}/2", fd_dir)) {
        let path = target.to_string_lossy().to_string();
        info.stderr_null = path == "/dev/null";
        if path.ends_with("/nohup.out") || path == "nohup.out" {
            info.nohup_output = true;
        }
        info.stderr_path = Some(path);
    }

    Ok(info)
}

#[cfg(not(target_os = "linux"))]
pub fn read_fd_info(_pid: u32) -> Result<FdInfo, NohupError> {
    Ok(FdInfo::default())
}

/// Check nohup.out file activity.
pub fn check_nohup_output_activity(pid: u32) -> Result<NohupOutputActivity, NohupError> {
    // First check if the process has nohup.out in its fd targets
    let fd_info = read_fd_info(pid)?;

    if !fd_info.nohup_output {
        // Also check current working directory for nohup.out
        #[cfg(target_os = "linux")]
        {
            let cwd_link = format!("/proc/{}/cwd", pid);
            if let Ok(cwd) = fs::read_link(&cwd_link) {
                let nohup_path = cwd.join("nohup.out");
                if nohup_path.exists() {
                    return check_file_activity(&nohup_path);
                }
            }
        }
        return Ok(NohupOutputActivity::None);
    }

    // Check the actual nohup.out file
    if let Some(ref stdout_path) = fd_info.stdout_path {
        if stdout_path.ends_with("/nohup.out") || stdout_path == "nohup.out" {
            let path = Path::new(stdout_path);
            if path.exists() {
                return check_file_activity(path);
            }
        }
    }

    Ok(NohupOutputActivity::None)
}

/// Check if a file is being actively written to.
fn check_file_activity(path: &Path) -> Result<NohupOutputActivity, NohupError> {
    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return Ok(NohupOutputActivity::None),
    };

    // Consider file "active" if modified in the last 5 minutes
    let modified = match metadata.modified() {
        Ok(t) => t,
        Err(_) => return Ok(NohupOutputActivity::Stale),
    };

    let age = match std::time::SystemTime::now().duration_since(modified) {
        Ok(d) => d,
        Err(_) => return Ok(NohupOutputActivity::Active), // Modified in future = recent
    };

    if age.as_secs() < 300 {
        // 5 minutes
        Ok(NohupOutputActivity::Active)
    } else {
        Ok(NohupOutputActivity::Stale)
    }
}

/// Analyzer for nohup/disown detection.
pub struct NohupAnalyzer {
    /// Threshold age in seconds for considering a process "old".
    pub stale_threshold_secs: u64,
}

impl NohupAnalyzer {
    /// Create a new analyzer with default settings.
    pub fn new() -> Self {
        Self {
            stale_threshold_secs: 300, // 5 minutes
        }
    }

    /// Detect nohup/disown status for a process.
    pub fn analyze(&self, pid: u32) -> Result<NohupResult, NohupError> {
        let mut result = NohupResult::not_background();
        let mut evidence = Vec::new();
        let mut confidence: f64 = 0.0;

        // Check if SIGHUP is ignored
        if let Ok(ignores_sighup) = check_signal_mask(pid) {
            result.ignores_sighup = ignores_sighup;
            if ignores_sighup {
                evidence.push(SupervisionEvidence {
                    evidence_type: EvidenceType::SignalMask,
                    description: "Process ignores SIGHUP".to_string(),
                    weight: 0.4,
                });
                confidence += 0.4;
            }
        }

        // Check if orphaned (PPID=1)
        if let Ok(ppid) = read_ppid(pid) {
            result.is_orphaned = ppid == 1;
            if result.is_orphaned && result.ignores_sighup {
                evidence.push(SupervisionEvidence {
                    evidence_type: EvidenceType::Ancestry,
                    description: "Process is orphaned (PPID=1)".to_string(),
                    weight: 0.2,
                });
                confidence += 0.2;
            }
        }

        // Check for nohup in command line
        if let Ok(has_nohup) = detect_nohup_command(pid) {
            result.has_nohup_cmd = has_nohup;
            if has_nohup {
                evidence.push(SupervisionEvidence {
                    evidence_type: EvidenceType::CommandLine,
                    description: "Command line contains 'nohup'".to_string(),
                    weight: 0.6,
                });
                confidence += 0.6;
            }
        }

        // Check file descriptors for nohup.out or /dev/null
        if let Ok(fd_info) = read_fd_info(pid) {
            result.has_nohup_output = fd_info.nohup_output;
            if fd_info.nohup_output {
                evidence.push(SupervisionEvidence {
                    evidence_type: EvidenceType::FileDescriptor,
                    description: "Output redirected to nohup.out".to_string(),
                    weight: 0.5,
                });
                confidence += 0.5;
            } else if fd_info.stdout_null && fd_info.stderr_null {
                evidence.push(SupervisionEvidence {
                    evidence_type: EvidenceType::FileDescriptor,
                    description: "stdout/stderr redirected to /dev/null".to_string(),
                    weight: 0.3,
                });
                confidence += 0.3;
            }
        }

        // Check nohup.out activity
        if let Ok(activity) = check_nohup_output_activity(pid) {
            result.nohup_output_activity = Some(activity.clone());
            match activity {
                NohupOutputActivity::Active => {
                    evidence.push(SupervisionEvidence {
                        evidence_type: EvidenceType::FileActivity,
                        description: "nohup.out is actively being written".to_string(),
                        weight: 0.3,
                    });
                }
                NohupOutputActivity::Stale => {
                    evidence.push(SupervisionEvidence {
                        evidence_type: EvidenceType::FileActivity,
                        description: "nohup.out exists but is stale".to_string(),
                        weight: 0.1,
                    });
                }
                NohupOutputActivity::None => {}
            }
        }

        // Normalize confidence to 0.0-1.0
        result.confidence = confidence.min(1.0);

        // Determine if this is a background process
        result.is_background = result.ignores_sighup
            || result.has_nohup_cmd
            || result.has_nohup_output
            || (result.is_orphaned
                && (fd_info_suggests_background(pid).unwrap_or(false)));

        // Infer intent
        result.inferred_intent = self.infer_intent(&result);
        result.evidence = evidence;

        Ok(result)
    }

    /// Infer whether the backgrounding was intentional or accidental.
    fn infer_intent(&self, result: &NohupResult) -> BackgroundIntent {
        if !result.is_background {
            return BackgroundIntent::Unknown;
        }

        // nohup.out active + nohup command = intentional, active
        if result.has_nohup_cmd
            && result.nohup_output_activity == Some(NohupOutputActivity::Active)
        {
            return BackgroundIntent::Intentional;
        }

        // nohup.out stale + old orphan = likely forgotten
        if result.is_orphaned
            && result.nohup_output_activity == Some(NohupOutputActivity::Stale)
        {
            return BackgroundIntent::Forgotten;
        }

        // No nohup.out, orphaned, ignores SIGHUP = probably disowned, possibly forgotten
        if result.is_orphaned
            && result.ignores_sighup
            && result.nohup_output_activity == Some(NohupOutputActivity::None)
        {
            return BackgroundIntent::Forgotten;
        }

        // Active nohup.out without nohup command = someone redirected manually, probably intentional
        if result.nohup_output_activity == Some(NohupOutputActivity::Active) {
            return BackgroundIntent::Intentional;
        }

        BackgroundIntent::Unknown
    }
}

impl Default for NohupAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if file descriptors suggest backgrounding.
fn fd_info_suggests_background(pid: u32) -> Result<bool, NohupError> {
    let info = read_fd_info(pid)?;
    Ok(info.stdout_null || info.stderr_null || info.nohup_output)
}

/// Convenience function to detect nohup/disown status.
pub fn detect_nohup(pid: u32) -> Result<NohupResult, NohupError> {
    let analyzer = NohupAnalyzer::new();
    analyzer.analyze(pid)
}

/// Convenience function to check if a process was disowned.
pub fn detect_disown(pid: u32) -> Result<bool, NohupError> {
    // Disown detection: orphaned process that ignores SIGHUP but wasn't started with nohup
    let ppid = read_ppid(pid)?;
    let ignores = check_signal_mask(pid).unwrap_or(false);
    let has_nohup = detect_nohup_command(pid).unwrap_or(false);

    // Disown: orphaned + ignores SIGHUP + no nohup in command
    Ok(ppid == 1 && ignores && !has_nohup)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_signal_mask() {
        let content = r#"Name:	test
State:	S (sleeping)
SigBlk:	0000000000000000
SigIgn:	0000000000000001
SigCgt:	0000000180000000
SigPnd:	0000000000000000
"#;
        let mask = parse_signal_mask(content, 1234).unwrap();
        assert!(mask.ignores_sighup());
        assert!(!mask.catches_sighup());
    }

    #[test]
    fn test_parse_signal_mask_no_sighup() {
        let content = r#"Name:	test
State:	S (sleeping)
SigBlk:	0000000000000000
SigIgn:	0000000000000000
SigCgt:	0000000180000000
SigPnd:	0000000000000000
"#;
        let mask = parse_signal_mask(content, 1234).unwrap();
        assert!(!mask.ignores_sighup());
    }

    #[test]
    fn test_signal_mask_bits() {
        // SIGHUP is signal 1, bit 0
        let mut mask = SignalMask::default();
        assert!(!mask.ignores_sighup());

        mask.ignored = 0x1; // bit 0 set
        assert!(mask.ignores_sighup());

        mask.caught = 0x1;
        assert!(mask.catches_sighup());
    }

    #[test]
    fn test_nohup_result_not_background() {
        let result = NohupResult::not_background();
        assert!(!result.is_background);
        assert!(!result.ignores_sighup);
        assert!(result.evidence.is_empty());
    }

    #[test]
    fn test_nohup_analyzer_new() {
        let analyzer = NohupAnalyzer::new();
        assert_eq!(analyzer.stale_threshold_secs, 300);
    }

    #[test]
    fn test_nohup_output_activity_eq() {
        assert_eq!(NohupOutputActivity::Active, NohupOutputActivity::Active);
        assert_ne!(NohupOutputActivity::Active, NohupOutputActivity::Stale);
    }

    #[test]
    fn test_background_intent_eq() {
        assert_eq!(BackgroundIntent::Intentional, BackgroundIntent::Intentional);
        assert_ne!(BackgroundIntent::Intentional, BackgroundIntent::Forgotten);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_read_signal_mask_current_process() {
        let pid = std::process::id();
        let result = read_signal_mask(pid);
        // Should succeed for current process
        assert!(result.is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_read_ppid_current_process() {
        let pid = std::process::id();
        let ppid = read_ppid(pid);
        assert!(ppid.is_ok());
        // PPID should be a valid PID (non-zero for non-init process)
        assert!(ppid.unwrap() > 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_nohup_current_process() {
        let pid = std::process::id();
        let result = detect_nohup(pid);
        // Should succeed for current process
        assert!(result.is_ok());
        // Test process probably wasn't started with nohup
        assert!(!result.unwrap().has_nohup_cmd);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_read_fd_info_current_process() {
        let pid = std::process::id();
        let result = read_fd_info(pid);
        assert!(result.is_ok());
    }
}
