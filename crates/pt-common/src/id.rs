//! Process and session identity types.
//!
//! These types ensure safe process identification across the codebase.
//! A process is uniquely identified by (pid, start_id, uid) tuple.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Process ID wrapper with display formatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProcessId(pub u32);

impl fmt::Display for ProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for ProcessId {
    fn from(pid: u32) -> Self {
        ProcessId(pid)
    }
}

/// Start ID - unique identifier for a specific process incarnation.
///
/// Format: `<boot_id_prefix>-<start_time_ticks>` (Linux)
/// or `<boot_id_prefix>-<pid>-<start_time>` (macOS)
///
/// This disambiguates PID reuse across reboots and within a boot.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StartId(pub String);

impl StartId {
    /// Create a new StartId from components (Linux).
    pub fn from_linux(boot_id_prefix: &str, start_time_ticks: u64) -> Self {
        StartId(format!("{}-{}", boot_id_prefix, start_time_ticks))
    }

    /// Create a new StartId from components (macOS).
    pub fn from_macos(boot_id_prefix: &str, pid: u32, start_time: u64) -> Self {
        StartId(format!("{}-{}-{}", boot_id_prefix, pid, start_time))
    }

    /// Parse and validate a StartId string.
    pub fn parse(s: &str) -> Option<Self> {
        // Basic validation: must have at least one hyphen
        if s.contains('-') && !s.is_empty() {
            Some(StartId(s.to_string()))
        } else {
            None
        }
    }
}

impl fmt::Display for StartId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Session ID for tracking triage sessions.
///
/// Format: `sess-<date>-<time>-<random>`
/// Example: `sess-20260115-143022-abc123`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub String);

impl SessionId {
    /// Generate a new session ID.
    pub fn new() -> Self {
        let now = chrono::Utc::now();
        let random: String = uuid::Uuid::new_v4()
            .to_string()
            .chars()
            .take(6)
            .collect();
        SessionId(format!(
            "sess-{}-{}",
            now.format("%Y%m%d-%H%M%S"),
            random
        ))
    }

    /// Parse an existing session ID string.
    pub fn parse(s: &str) -> Option<Self> {
        if s.starts_with("sess-") && s.len() > 20 {
            Some(SessionId(s.to_string()))
        } else {
            None
        }
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Complete process identity tuple for safe revalidation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: ProcessId,
    pub start_id: StartId,
    pub uid: u32,
}

impl ProcessIdentity {
    pub fn new(pid: u32, start_id: StartId, uid: u32) -> Self {
        ProcessIdentity {
            pid: ProcessId(pid),
            start_id,
            uid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_format() {
        let sid = SessionId::new();
        assert!(sid.0.starts_with("sess-"));
        assert!(sid.0.len() > 20);
    }

    #[test]
    fn test_start_id_linux() {
        let sid = StartId::from_linux("abc12345", 123456789);
        assert_eq!(sid.0, "abc12345-123456789");
    }

    #[test]
    fn test_start_id_macos() {
        let sid = StartId::from_macos("abc12345", 1234, 987654321);
        assert_eq!(sid.0, "abc12345-1234-987654321");
    }
}
