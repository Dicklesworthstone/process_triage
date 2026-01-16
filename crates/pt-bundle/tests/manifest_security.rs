use pt_bundle::{BundleManifest, FileEntry};
use pt_redact::ExportProfile;

#[test]
fn test_manifest_path_validation() {
    let mut manifest = BundleManifest::new("session-123", "host-abc", ExportProfile::Safe);

    // 1. Absolute path -> Should fail
    manifest.files.clear();
    manifest.add_file(FileEntry::new("/etc/passwd", "a".repeat(64), 100));
    assert!(manifest.validate().is_err(), "Should reject absolute path");

    // 2. Path with .. -> Should fail
    manifest.files.clear();
    manifest.add_file(FileEntry::new("../../../etc/passwd", "a".repeat(64), 100));
    assert!(manifest.validate().is_err(), "Should reject traversal (..)");

    // 3. Normal path -> Should pass
    manifest.files.clear();
    manifest.add_file(FileEntry::new("logs/audit.jsonl", "a".repeat(64), 100));
    assert!(manifest.validate().is_ok(), "Should accept normal path");
}
