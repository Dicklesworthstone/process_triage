//! Process and session identity types.
//!
//! These types ensure safe process identification across the codebase.
//! A process is uniquely identified by (pid, start_id, uid) tuple.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Process ID wrapper with display formatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
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
/// Format: `<boot_id>:<start_time_ticks>:<pid>` (Linux)
/// or `<boot_id>:<start_time>:<pid>` (macOS)
///
/// This disambiguates PID reuse across reboots and within a boot.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct StartId(pub String);

impl StartId {
    /// Create a new StartId from components (Linux).
    pub fn from_linux(boot_id: &str, start_time_ticks: u64, pid: u32) -> Self {
        StartId(format!("{}:{}:{}", boot_id, start_time_ticks, pid))
    }

    /// Create a new StartId from components (macOS).
    pub fn from_macos(boot_id: &str, start_time: u64, pid: u32) -> Self {
        StartId(format!("{}:{}:{}", boot_id, start_time, pid))
    }

    /// Parse and validate a StartId string.
    pub fn parse(s: &str) -> Option<Self> {
        let mut parts = s.split(':');
        let boot_id = parts.next()?;
        let start_time = parts.next()?;
        let pid = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        if uuid::Uuid::parse_str(boot_id).is_err() {
            return None;
        }
        if start_time.parse::<u64>().is_err() {
            return None;
        }
        if pid.parse::<u32>().is_err() {
            return None;
        }
        Some(StartId(s.to_string()))
    }
}

impl fmt::Display for StartId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Session ID for tracking triage sessions.
///
/// Format: `pt-YYYYMMDD-HHMMSS-XXXX`
/// Example: `pt-20260115-143022-a7xq`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct SessionId(pub String);

impl SessionId {
    /// Generate a new session ID.
    pub fn new() -> Self {
        let now = chrono::Utc::now();
        let suffix = generate_base32_suffix();
        SessionId(format!(
            "pt-{}-{}-{}",
            now.format("%Y%m%d"),
            now.format("%H%M%S"),
            suffix
        ))
    }

    /// Parse an existing session ID string.
    pub fn parse(s: &str) -> Option<Self> {
        if s.len() != 23 {
            return None;
        }
        let bytes = s.as_bytes();
        if bytes.first() != Some(&b'p')
            || bytes.get(1) != Some(&b't')
            || bytes.get(2) != Some(&b'-')
            || bytes.get(11) != Some(&b'-')
            || bytes.get(18) != Some(&b'-')
        {
            return None;
        }
        let date = &s[3..11];
        let time = &s[12..18];
        let suffix = &s[19..23];
        if !date.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        if !time.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        if !suffix.chars().all(|c| matches!(c, 'a'..='z' | '2'..='7')) {
            return None;
        }
        Some(SessionId(s.to_string()))
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

/// Quality/provenance indicator for process identity.
///
/// Indicates how reliable the identity tuple is for TOCTOU protection.
/// When identity quality is degraded, safety gates should be tightened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum IdentityQuality {
    /// Full identity available: boot_id + start_time_ticks + pid.
    /// Strongest guarantee against PID reuse.
    Full,

    /// Boot ID unavailable but start_time available.
    /// Safe within a single boot but weaker across reboots.
    NoBootId,

    /// Start time unavailable (fallback to pid-only).
    /// Weakest identity - PID reuse cannot be detected.
    PidOnly,
}

impl IdentityQuality {
    /// Returns true if identity is strong enough for automated actions.
    pub fn is_automatable(&self) -> bool {
        matches!(self, IdentityQuality::Full | IdentityQuality::NoBootId)
    }

    /// Returns true if identity requires extra safety gates.
    pub fn requires_safety_gates(&self) -> bool {
        matches!(self, IdentityQuality::NoBootId | IdentityQuality::PidOnly)
    }
}

impl fmt::Display for IdentityQuality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityQuality::Full => write!(f, "full"),
            IdentityQuality::NoBootId => write!(f, "no_boot_id"),
            IdentityQuality::PidOnly => write!(f, "pid_only"),
        }
    }
}

/// Complete process identity tuple for safe revalidation.
///
/// The tuple (pid, start_id, uid, boot_id) is sufficient to detect
/// PID reuse across time and across session resumes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ProcessIdentity {
    /// Process ID.
    pub pid: ProcessId,

    /// Start ID for PID-reuse detection.
    pub start_id: StartId,

    /// User ID (owner of the process).
    pub uid: u32,

    /// Process group ID (for group-aware actions).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pgid: Option<u32>,

    /// Session ID (for session-aware safety gates).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<u32>,

    /// Identity quality/provenance indicator.
    pub quality: IdentityQuality,
}

impl ProcessIdentity {
    /// Create a new ProcessIdentity with full quality.
    pub fn new(pid: u32, start_id: StartId, uid: u32) -> Self {
        ProcessIdentity {
            pid: ProcessId(pid),
            start_id,
            uid,
            pgid: None,
            sid: None,
            quality: IdentityQuality::Full,
        }
    }

    /// Create a ProcessIdentity with all fields.
    pub fn full(
        pid: u32,
        start_id: StartId,
        uid: u32,
        pgid: Option<u32>,
        sid: Option<u32>,
        quality: IdentityQuality,
    ) -> Self {
        ProcessIdentity {
            pid: ProcessId(pid),
            start_id,
            uid,
            pgid,
            sid,
            quality,
        }
    }

    /// Check if this identity matches another (for revalidation).
    ///
    /// Returns true if both identities refer to the same process incarnation.
    pub fn matches(&self, other: &ProcessIdentity) -> bool {
        self.pid == other.pid && self.start_id == other.start_id && self.uid == other.uid
    }

    /// Check if a revalidation should be trusted.
    ///
    /// Returns false if identity quality is too weak for safe revalidation.
    pub fn can_safely_revalidate(&self) -> bool {
        self.quality.is_automatable()
    }
}

fn generate_base32_suffix() -> String {
    let uuid = uuid::Uuid::new_v4();
    let bytes = uuid.as_bytes();
    let mut value = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32);
    value &= 0x000F_FFFF;
    let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(4);
    for shift in [15_u32, 10, 5, 0] {
        let idx = ((value >> shift) & 0x1F) as usize;
        out.push(alphabet[idx] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_format() {
        let sid = SessionId::new();
        assert!(sid.0.starts_with("pt-"));
        assert_eq!(sid.0.len(), 23);
    }

    #[test]
    fn test_start_id_linux() {
        let sid = StartId::from_linux("9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f", 123456789, 4242);
        assert_eq!(sid.0, "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:123456789:4242");
    }

    #[test]
    fn test_start_id_macos() {
        let sid = StartId::from_macos("9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f", 987654321, 1234);
        assert_eq!(sid.0, "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:987654321:1234");
    }

    #[test]
    fn test_identity_quality_automatable() {
        assert!(IdentityQuality::Full.is_automatable());
        assert!(IdentityQuality::NoBootId.is_automatable());
        assert!(!IdentityQuality::PidOnly.is_automatable());
    }

    #[test]
    fn test_identity_quality_safety_gates() {
        assert!(!IdentityQuality::Full.requires_safety_gates());
        assert!(IdentityQuality::NoBootId.requires_safety_gates());
        assert!(IdentityQuality::PidOnly.requires_safety_gates());
    }

    #[test]
    fn test_identity_quality_display() {
        assert_eq!(format!("{}", IdentityQuality::Full), "full");
        assert_eq!(format!("{}", IdentityQuality::NoBootId), "no_boot_id");
        assert_eq!(format!("{}", IdentityQuality::PidOnly), "pid_only");
    }

    #[test]
    fn test_process_identity_new() {
        let start_id = StartId::from_linux("boot-id-123", 12345, 100);
        let identity = ProcessIdentity::new(100, start_id.clone(), 1000);

        assert_eq!(identity.pid.0, 100);
        assert_eq!(identity.start_id, start_id);
        assert_eq!(identity.uid, 1000);
        assert_eq!(identity.pgid, None);
        assert_eq!(identity.sid, None);
        assert_eq!(identity.quality, IdentityQuality::Full);
    }

    #[test]
    fn test_process_identity_full() {
        let start_id = StartId::from_linux("boot-id-456", 67890, 200);
        let identity = ProcessIdentity::full(
            200,
            start_id.clone(),
            1000,
            Some(200),
            Some(200),
            IdentityQuality::NoBootId,
        );

        assert_eq!(identity.pid.0, 200);
        assert_eq!(identity.pgid, Some(200));
        assert_eq!(identity.sid, Some(200));
        assert_eq!(identity.quality, IdentityQuality::NoBootId);
    }

    #[test]
    fn test_process_identity_matches() {
        let start_id = StartId::from_linux("boot-id", 12345, 100);
        let id1 = ProcessIdentity::new(100, start_id.clone(), 1000);
        let id2 = ProcessIdentity::new(100, start_id.clone(), 1000);
        let id3 = ProcessIdentity::new(100, start_id.clone(), 1001); // Different UID

        assert!(id1.matches(&id2));
        assert!(!id1.matches(&id3));
    }

    #[test]
    fn test_process_identity_can_safely_revalidate() {
        let start_id = StartId::from_linux("boot-id", 12345, 100);

        let full = ProcessIdentity::full(
            100,
            start_id.clone(),
            1000,
            None,
            None,
            IdentityQuality::Full,
        );
        assert!(full.can_safely_revalidate());

        let no_boot = ProcessIdentity::full(
            100,
            start_id.clone(),
            1000,
            None,
            None,
            IdentityQuality::NoBootId,
        );
        assert!(no_boot.can_safely_revalidate());

        let pid_only =
            ProcessIdentity::full(100, start_id, 1000, None, None, IdentityQuality::PidOnly);
        assert!(!pid_only.can_safely_revalidate());
    }
}
