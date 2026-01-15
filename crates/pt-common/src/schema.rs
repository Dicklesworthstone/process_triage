//! Schema versioning and compatibility.

/// Current schema version for all JSON outputs.
///
/// Follows semver: MAJOR.MINOR.PATCH
/// - MAJOR: Breaking changes (field removals, type changes)
/// - MINOR: Additive changes (new optional fields)
/// - PATCH: Bug fixes, documentation
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Minimum supported schema version for session resumption.
pub const MIN_COMPATIBLE_VERSION: &str = "1.0.0";

/// Check if a schema version is compatible with current.
pub fn is_compatible(version: &str) -> bool {
    // Parse major versions and compare
    let current_major = SCHEMA_VERSION
        .split('.')
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    let other_major = version
        .split('.')
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    current_major == other_major
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_same_major_compatible() {
        assert!(is_compatible("1.0.0"));
        assert!(is_compatible("1.1.0"));
        assert!(is_compatible("1.99.99"));
    }

    #[test]
    fn test_different_major_incompatible() {
        assert!(!is_compatible("0.9.0"));
        assert!(!is_compatible("2.0.0"));
    }
}
