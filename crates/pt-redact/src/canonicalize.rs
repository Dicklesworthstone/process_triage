//! Canonicalization for stable pattern matching.
//!
//! Normalizes inputs before hashing to enable pattern matching while
//! removing variable parts like PIDs, timestamps, and user-specific paths.

use once_cell::sync::Lazy;
use regex::Regex;

/// Current canonicalization version. Changes when rules are modified.
pub const CANONICALIZATION_VERSION: &str = "1.0.0";

/// Canonicalizer for normalizing values before hashing.
#[derive(Clone)]
pub struct Canonicalizer {
    /// Home directory pattern (detected at runtime).
    home_dir: Option<String>,
    /// Additional patterns to normalize.
    custom_patterns: Vec<(Regex, &'static str)>,
}

// Pre-compiled regex patterns for canonicalization
static RE_UUID: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
        .unwrap()
});

static RE_TIMESTAMP_ISO: Lazy<Regex> = Lazy::new(|| {
    // Case-insensitive because we lowercase before matching
    Regex::new(r"(?i)\d{4}-\d{2}-\d{2}t\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:z|[+-]\d{2}:?\d{2})?").unwrap()
});

static RE_TIMESTAMP_UNIX: Lazy<Regex> = Lazy::new(|| {
    // Unix timestamps (10-13 digits, reasonable range 2000-2100)
    Regex::new(r"\b(9[0-9]{8}|1[0-9]{9,12})\b").unwrap()
});

static RE_PID_ARG: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"--pid[=\s]+\d+").unwrap());

static RE_PORT_ARG: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"--port[=\s]+\d+").unwrap());

static RE_TMP_SESSION: Lazy<Regex> = Lazy::new(|| {
    // Matches /tmp/pytest-123, /tmp/tmp.abc123, /var/tmp/session-456
    // Captures the full session directory including trailing slash if present
    Regex::new(r"(/tmp|/var/tmp)/[a-zA-Z_][a-zA-Z0-9_.-]*").unwrap()
});

static RE_NUMERIC_SUFFIX: Lazy<Regex> = Lazy::new(|| {
    // Matches _123, -456, .789 at end of words
    Regex::new(r"([_.-])\d+\b").unwrap()
});

static RE_URL_CRED: Lazy<Regex> = Lazy::new(|| {
    // user:pass@ in URLs
    Regex::new(r"://[^:/@]+:[^@]+@").unwrap()
});

static RE_URL_PORT: Lazy<Regex> = Lazy::new(|| {
    // Port numbers in URLs (2-5 digits followed by / or end)
    Regex::new(r":(\d{2,5})(/|$)").unwrap()
});

static RE_MULTIPLE_SPACES: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+").unwrap());

impl Canonicalizer {
    /// Create a new canonicalizer.
    pub fn new() -> Self {
        // Try to detect home directory
        let home_dir = std::env::var("HOME").ok().or_else(|| {
            std::env::var("USERPROFILE").ok()
        });

        Self {
            home_dir,
            custom_patterns: Vec::new(),
        }
    }

    /// Create a canonicalizer with a specific home directory.
    pub fn with_home_dir(home_dir: &str) -> Self {
        Self {
            home_dir: Some(home_dir.to_string()),
            custom_patterns: Vec::new(),
        }
    }

    /// Canonicalize a value for stable hashing.
    ///
    /// Applies the following transformations in order:
    /// 1. Trim leading/trailing whitespace
    /// 2. Collapse multiple spaces to single space
    /// 3. Convert to lowercase
    /// 4. Replace home directory with [HOME]
    /// 5. Replace temp directories with [TMP]
    /// 6. Replace PIDs with [PID]
    /// 7. Replace ports with [PORT]
    /// 8. Replace UUIDs with [UUID]
    /// 9. Replace timestamps with [TIMESTAMP]
    /// 10. Replace numeric suffixes with [N]
    /// 11. Replace URL credentials with [CRED]
    pub fn canonicalize(&self, input: &str) -> String {
        let mut result = input.to_string();

        // 1. Trim whitespace
        result = result.trim().to_string();

        // 2. Collapse multiple spaces
        result = RE_MULTIPLE_SPACES.replace_all(&result, " ").to_string();

        // 3. Convert to lowercase
        result = result.to_lowercase();

        // 4. Replace home directory
        if let Some(ref home) = self.home_dir {
            let home_lower = home.to_lowercase();
            if result.contains(&home_lower) {
                result = result.replace(&home_lower, "[HOME]");
            }
        }

        // 5. Replace temp directories
        result = RE_TMP_SESSION.replace_all(&result, "[TMP]").to_string();
        // Also handle simple /tmp/ paths
        result = result.replace("/tmp/", "[TMP]/");
        result = result.replace("/var/tmp/", "[TMP]/");

        // 6. Replace PID arguments
        result = RE_PID_ARG.replace_all(&result, "--pid [PID]").to_string();

        // 7. Replace port arguments
        result = RE_PORT_ARG.replace_all(&result, "--port [PORT]").to_string();

        // 8. Replace UUIDs
        result = RE_UUID.replace_all(&result, "[UUID]").to_string();

        // 9. Replace timestamps
        result = RE_TIMESTAMP_ISO
            .replace_all(&result, "[TIMESTAMP]")
            .to_string();
        result = RE_TIMESTAMP_UNIX
            .replace_all(&result, "[TIMESTAMP]")
            .to_string();

        // 10. Replace numeric suffixes (but not in [PLACEHOLDERS])
        // Only apply to parts outside brackets
        result = canonicalize_numeric_suffixes(&result);

        // 11. Replace URL credentials
        result = RE_URL_CRED.replace_all(&result, "://[CRED]@").to_string();

        // Apply custom patterns
        for (pattern, replacement) in &self.custom_patterns {
            result = pattern.replace_all(&result, *replacement).to_string();
        }

        result
    }

    /// Canonicalize a path specifically.
    pub fn canonicalize_path(&self, path: &str) -> String {
        let mut result = path.to_string();

        // Replace home directory
        if let Some(ref home) = self.home_dir {
            if result.starts_with(home) {
                result = format!("[HOME]{}", &result[home.len()..]);
            }
        }

        // Replace temp session directories first (more specific)
        // Match patterns like /tmp/pytest-123, /tmp/session-abc, etc.
        if let Some(caps) = RE_TMP_SESSION.find(&result) {
            // Keep anything after the session directory
            let after_session = &result[caps.end()..];
            result = format!("[TMP]{}", after_session);
        } else if result.starts_with("/tmp/") {
            result = format!("[TMP]{}", &result[4..]);
        } else if result.starts_with("/var/tmp/") {
            result = format!("[TMP]{}", &result[8..]);
        }

        result
    }

    /// Canonicalize a URL specifically.
    pub fn canonicalize_url(&self, url: &str) -> String {
        let mut result = url.to_string();

        // Remove credentials first (before lowercasing)
        result = RE_URL_CRED.replace_all(&result, "://[CRED]@").to_string();

        // Normalize port numbers in URLs
        result = RE_URL_PORT.replace_all(&result, ":[PORT]$2").to_string();

        // Lowercase everything except placeholders
        let mut lowered = String::with_capacity(result.len());
        let mut in_bracket = false;
        for ch in result.chars() {
            if ch == '[' {
                in_bracket = true;
                lowered.push(ch);
            } else if ch == ']' {
                in_bracket = false;
                lowered.push(ch);
            } else if in_bracket {
                lowered.push(ch);
            } else {
                lowered.push(ch.to_ascii_lowercase());
            }
        }
        lowered
    }
}

impl Default for Canonicalizer {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to replace numeric suffixes while preserving [PLACEHOLDER] tokens.
fn canonicalize_numeric_suffixes(input: &str) -> String {
    let mut result = String::with_capacity(input.len());

    // Simple approach: only replace suffixes not inside brackets
    // Split on brackets, process, rejoin
    let parts: Vec<&str> = input.split('[').collect();
    let mut first = true;
    for part in parts {
        if first {
            // No leading bracket
            result.push_str(&RE_NUMERIC_SUFFIX.replace_all(part, "${1}[N]"));
            first = false;
        } else if let Some(bracket_end) = part.find(']') {
            // Part starts inside a bracket
            result.push('[');
            result.push_str(&part[..=bracket_end]);
            // After the bracket, apply numeric suffix replacement
            result.push_str(&RE_NUMERIC_SUFFIX.replace_all(&part[bracket_end + 1..], "${1}[N]"));
        } else {
            // Malformed, just keep as-is
            result.push('[');
            result.push_str(part);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trim_and_collapse() {
        let canon = Canonicalizer::new();
        assert_eq!(canon.canonicalize("  foo    bar  "), "foo bar");
    }

    #[test]
    fn test_lowercase() {
        let canon = Canonicalizer::new();
        assert_eq!(canon.canonicalize("FOO BAR"), "foo bar");
    }

    #[test]
    fn test_home_directory() {
        let canon = Canonicalizer::with_home_dir("/home/alice");
        assert_eq!(
            canon.canonicalize("/home/alice/project/src"),
            "[HOME]/project/src"
        );
    }

    #[test]
    fn test_tmp_directory() {
        let canon = Canonicalizer::new();
        assert_eq!(
            canon.canonicalize("/tmp/pytest-123/test.log"),
            "[TMP]/test.log"
        );
    }

    #[test]
    fn test_pid_placeholder() {
        let canon = Canonicalizer::new();
        assert_eq!(
            canon.canonicalize("kill --pid 12345"),
            "kill --pid [PID]"
        );
    }

    #[test]
    fn test_port_placeholder() {
        let canon = Canonicalizer::new();
        assert_eq!(
            canon.canonicalize("server --port 3000"),
            "server --port [PORT]"
        );
    }

    #[test]
    fn test_uuid_placeholder() {
        let canon = Canonicalizer::new();
        let result = canon.canonicalize("container a1b2c3d4-e5f6-7890-abcd-ef1234567890");
        assert_eq!(result, "container [UUID]");
    }

    #[test]
    fn test_timestamp_placeholder() {
        let canon = Canonicalizer::new();
        let result = canon.canonicalize("log at 2026-01-15T14:30:22Z");
        assert_eq!(result, "log at [TIMESTAMP]");
    }

    #[test]
    fn test_url_credentials() {
        let canon = Canonicalizer::new();
        let result = canon.canonicalize("https://user:secret@api.example.com/path");
        assert!(result.contains("[CRED]"));
        assert!(!result.contains("secret"));
    }

    #[test]
    fn test_numeric_suffix() {
        let canon = Canonicalizer::new();
        let result = canon.canonicalize("test_1234");
        assert_eq!(result, "test_[N]");
    }

    #[test]
    fn test_complex_cmdline() {
        let canon = Canonicalizer::with_home_dir("/home/alice");
        let input = "/home/alice/project/bin/test --port 3000 --pid 12345";
        let result = canon.canonicalize(input);
        assert!(result.contains("[HOME]"));
        assert!(result.contains("[PORT]"));
        assert!(result.contains("[PID]"));
        assert!(!result.contains("alice"));
        assert!(!result.contains("3000"));
        assert!(!result.contains("12345"));
    }

    #[test]
    fn test_canonicalize_path() {
        let canon = Canonicalizer::with_home_dir("/home/bob");
        assert_eq!(
            canon.canonicalize_path("/home/bob/.config/app"),
            "[HOME]/.config/app"
        );
        assert_eq!(
            canon.canonicalize_path("/tmp/session-123/data"),
            "[TMP]/data"
        );
    }

    #[test]
    fn test_canonicalize_url() {
        let canon = Canonicalizer::new();
        let result = canon.canonicalize_url("https://admin:pass123@api.example.com:8443/v1");
        assert!(result.contains("[CRED]"));
        assert!(result.contains("[PORT]"));
        assert!(!result.contains("pass123"));
    }
}
