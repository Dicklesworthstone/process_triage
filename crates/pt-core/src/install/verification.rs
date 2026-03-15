//! Post-update verification for installed binaries.

use std::io;
use std::path::Path;
use std::process::{Command, Output};
use std::time::Duration;

use super::DEFAULT_VERIFICATION_TIMEOUT_SECS;

/// Result of a verification check
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the verification passed
    pub passed: bool,
    /// The version string if extracted
    pub version: Option<String>,
    /// Health check output if available
    pub health_output: Option<String>,
    /// Error message if verification failed
    pub error: Option<String>,
    /// Duration of verification
    pub duration_ms: u64,
}

impl VerificationResult {
    /// Create a successful result
    pub fn success(
        version: Option<String>,
        health_output: Option<String>,
        duration_ms: u64,
    ) -> Self {
        Self {
            passed: true,
            version,
            health_output,
            error: None,
            duration_ms,
        }
    }

    /// Create a failed result
    pub fn failure(error: String, duration_ms: u64) -> Self {
        Self {
            passed: false,
            version: None,
            health_output: None,
            error: Some(error),
            duration_ms,
        }
    }
}

/// Verify a binary after installation
///
/// Runs:
/// 1. `binary --version` to check it starts and returns a version
/// 2. `binary health` (if available) to verify basic functionality
pub fn verify_binary(
    binary_path: &Path,
    expected_version: Option<&str>,
) -> io::Result<VerificationResult> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(DEFAULT_VERIFICATION_TIMEOUT_SECS);

    // Check binary exists and is executable
    if !binary_path.exists() {
        return Ok(VerificationResult::failure(
            "Binary does not exist".to_string(),
            start.elapsed().as_millis() as u64,
        ));
    }

    // Run --version check
    let version_result = run_with_timeout(binary_path, &["--version"], timeout);

    let version = match version_result {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let combined = format!("{}{}", stdout, stderr);

            // Extract version number (e.g., "1.2.3" or "v1.2.3")
            extract_version(&combined)
        }
        Ok(output) => {
            return Ok(VerificationResult::failure(
                format!(
                    "Version check failed with exit code {:?}: {}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stderr)
                ),
                start.elapsed().as_millis() as u64,
            ));
        }
        Err(e) => {
            return Ok(VerificationResult::failure(
                format!("Failed to run version check: {}", e),
                start.elapsed().as_millis() as u64,
            ));
        }
    };

    // Verify version matches expected if provided
    if let Some(expected) = expected_version {
        match version.as_deref() {
            Some(actual) => {
                if !versions_match(actual, expected) {
                    return Ok(VerificationResult::failure(
                        format!("Version mismatch: expected {}, got {}", expected, actual),
                        start.elapsed().as_millis() as u64,
                    ));
                }
            }
            None => {
                return Ok(VerificationResult::failure(
                    "Version check succeeded but output was unparseable".to_string(),
                    start.elapsed().as_millis() as u64,
                ));
            }
        }
    }

    // Try health check (optional, may not be implemented)
    let health_output = run_with_timeout(binary_path, &["health"], timeout)
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string());

    Ok(VerificationResult::success(
        version,
        health_output,
        start.elapsed().as_millis() as u64,
    ))
}

/// Run a command with a timeout
fn run_with_timeout(binary: &Path, args: &[&str], timeout: Duration) -> io::Result<Output> {
    use std::process::Stdio;

    let mut child = Command::new(binary)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Wait with timeout
    let start = std::time::Instant::now();
    loop {
        match child.try_wait()? {
            Some(status) => {
                // Process completed
                let stdout = child.stdout.take().map_or(Vec::new(), |mut s| {
                    let mut buf = Vec::new();
                    let _ = std::io::Read::read_to_end(&mut s, &mut buf);
                    buf
                });
                let stderr = child.stderr.take().map_or(Vec::new(), |mut s| {
                    let mut buf = Vec::new();
                    let _ = std::io::Read::read_to_end(&mut s, &mut buf);
                    buf
                });

                return Ok(Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            None => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("Command timed out after {:?}", timeout),
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Extract version string from output
fn extract_version(output: &str) -> Option<String> {
    // Try common version patterns
    // Pattern 1: "pt-core 1.2.3" or "pt 1.2.3"
    // Pattern 2: "version 1.2.3" or "v1.2.3"
    // Pattern 3: Just "1.2.3"

    let version_regex =
        regex::Regex::new(r"(?:version\s+|v)?(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)").ok()?;

    version_regex
        .captures(output)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

/// Check if two version strings match
fn versions_match(actual: &str, expected: &str) -> bool {
    // Strip leading 'v' if present
    let actual = actual.trim_start_matches('v');
    let expected = expected.trim_start_matches('v');

    // Compare normalized versions
    actual == expected
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use tempfile::TempDir;

    #[test]
    fn test_extract_version() {
        assert_eq!(extract_version("pt-core 1.2.3"), Some("1.2.3".to_string()));
        assert_eq!(extract_version("version 1.2.3"), Some("1.2.3".to_string()));
        assert_eq!(extract_version("v1.2.3"), Some("1.2.3".to_string()));
        assert_eq!(extract_version("1.2.3"), Some("1.2.3".to_string()));
        assert_eq!(
            extract_version("pt-core 1.2.3-beta.1"),
            Some("1.2.3-beta.1".to_string())
        );
        assert_eq!(extract_version("no version here"), None);
    }

    #[test]
    fn test_versions_match() {
        assert!(versions_match("1.2.3", "1.2.3"));
        assert!(versions_match("v1.2.3", "1.2.3"));
        assert!(versions_match("1.2.3", "v1.2.3"));
        assert!(!versions_match("1.2.3", "1.2.4"));
        assert!(!versions_match("1.2.3", "2.0.0"));
    }

    #[test]
    fn test_verify_nonexistent_binary() {
        let result = verify_binary(Path::new("/nonexistent/binary"), None).unwrap();
        assert!(!result.passed);
        assert!(result.error.unwrap().contains("does not exist"));
    }

    #[cfg(unix)]
    #[test]
    fn test_verify_expected_version_unparseable() {
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join("pt-core-test");
        fs::write(
            &script_path,
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  echo \"version unknown\"\n  exit 0\nfi\nexit 1\n",
        )
        .unwrap();
        let mut perms = fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));

        let result = verify_binary(&script_path, Some("1.2.3")).unwrap();
        assert!(!result.passed, "Expected failure but got success");
        assert!(
            result.error.unwrap_or_default().contains("unparseable"),
            "Expected 'unparseable' error"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_run_with_timeout_times_out() {
        let temp = TempDir::new().unwrap();
        let script_path = temp.path().join("pt-core-timeout");
        fs::write(&script_path, "#!/bin/sh\nsleep 2\n").unwrap();
        let mut perms = fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));

        let err = run_with_timeout(&script_path, &[], Duration::from_millis(100)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }
}
