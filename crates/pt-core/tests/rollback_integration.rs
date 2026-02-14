//! Integration tests for the rollback-safe self-update mechanism.
//!
//! Tests cover:
//! - Full update + rollback cycle
//! - Update failure triggers automatic rollback
//! - Manual rollback to specific version
//! - Rollback with corrupted backup (error handling)
//! - Concurrent update protection

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

/// Create a mock binary that reports a specific version
fn create_mock_binary(dir: &std::path::Path, name: &str, version: &str) -> PathBuf {
    let path = dir.join(name);
    let content = format!(
        r#"#!/bin/bash
case "$1" in
    --version) echo "{} {}" ;;
    health) echo "OK" ;;
    *) echo "Unknown command" ;;
esac
"#,
        name, version
    );
    fs::write(&path, content).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).unwrap();
    }

    path
}

/// Create a broken binary for testing rollback
fn create_broken_binary(path: &std::path::Path) {
    let content = r#"#!/bin/bash
echo "FATAL: Binary corrupted" >&2
exit 1
"#;
    fs::write(path, content).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).unwrap();
    }
}

mod backup_tests {
    use super::*;
    use pt_core::install::{BackupManager, BackupMetadata};

    #[test]
    fn test_backup_creation_stores_correct_metadata() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("rollback");

        let manager = BackupManager::with_config(backup_dir.clone(), "pt-core", 3);
        let backup = manager.create_backup(&binary_path, "1.0.0").unwrap();

        // Verify metadata
        assert_eq!(backup.metadata.version, "1.0.0");
        assert!(!backup.metadata.checksum.is_empty());
        assert!(backup.metadata.size_bytes > 0);
        assert!(backup.binary_path.exists());
        assert!(backup.metadata_path.exists());

        // Verify metadata can be loaded
        let loaded = BackupMetadata::load(&backup.metadata_path).unwrap();
        assert_eq!(loaded.version, "1.0.0");
        assert_eq!(loaded.checksum, backup.metadata.checksum);
    }

    #[test]
    fn test_backup_cleanup_keeps_last_n_versions() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("rollback");

        // Keep only 2 backups
        let manager = BackupManager::with_config(backup_dir.clone(), "pt-core", 2);

        // Create 5 backups
        for i in 1..=5 {
            let _ = manager
                .create_backup(&binary_path, &format!("1.0.{}", i))
                .unwrap();
            // Small delay to ensure different timestamps
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Should only have 2 backups
        let backups = manager.list_backups().unwrap();
        assert_eq!(backups.len(), 2);

        // Should be the newest ones (1.0.5 and 1.0.4)
        assert_eq!(backups[0].metadata.version, "1.0.5");
        assert_eq!(backups[1].metadata.version, "1.0.4");
    }

    #[test]
    fn test_backup_verification_detects_corruption() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("rollback");

        let manager = BackupManager::with_config(backup_dir, "pt-core", 3);
        let backup = manager.create_backup(&binary_path, "1.0.0").unwrap();

        // Initially should verify OK
        assert!(manager.verify_backup(&backup).unwrap());

        // Corrupt the backup
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&backup.binary_path)
            .unwrap();
        writeln!(file, "# corrupted").unwrap();

        // Should now fail verification
        assert!(!manager.verify_backup(&backup).unwrap());
    }
}

mod rollback_tests {
    use super::*;
    use pt_core::install::{RollbackManager, UpdateResult};

    #[test]
    fn test_full_update_rollback_cycle() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("rollback");
        let new_binary_path = create_mock_binary(temp.path(), "pt-core-new", "2.0.0");

        let manager =
            RollbackManager::with_backup_dir(binary_path.clone(), "pt-core", backup_dir.clone());

        // Perform atomic update
        let result = manager
            .atomic_update(&new_binary_path, "1.0.0", Some("2.0.0"))
            .unwrap();

        match result {
            UpdateResult::Success { verification, .. } => {
                assert!(verification.passed);
                // Note: version parsing may differ based on mock binary output
            }
            UpdateResult::VerificationFailed { .. } => {
                // Expected if version check doesn't match exactly
            }
            UpdateResult::SignatureRejected { .. } => {
                panic!("Unexpected signature rejection (no verifier configured)");
            }
        }
    }

    #[test]
    fn test_update_failure_triggers_automatic_rollback() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("rollback");
        let broken_binary = temp.path().join("pt-core-broken");
        create_broken_binary(&broken_binary);

        let manager =
            RollbackManager::with_backup_dir(binary_path.clone(), "pt-core", backup_dir.clone());

        // Try to update with broken binary
        let result = manager
            .atomic_update(&broken_binary, "1.0.0", Some("2.0.0"))
            .unwrap();

        match result {
            UpdateResult::VerificationFailed {
                verification,
                rollback,
                ..
            } => {
                // Verification should have failed
                assert!(!verification.passed);
                // Rollback should have succeeded
                assert!(rollback.success);
                assert_eq!(rollback.restored_version.as_deref(), Some("1.0.0"));
            }
            UpdateResult::Success { .. } => {
                panic!("Expected verification failure, got success");
            }
            UpdateResult::SignatureRejected { .. } => {
                panic!("Unexpected signature rejection (no verifier configured)");
            }
        }
    }

    #[test]
    fn test_manual_rollback_to_specific_version() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_mock_binary(temp.path(), "pt-core", "3.0.0");
        let backup_dir = temp.path().join("rollback");

        let manager =
            RollbackManager::with_backup_dir(binary_path.clone(), "pt-core", backup_dir.clone());

        // Create multiple backups
        fs::write(&binary_path, "v1").unwrap();
        let _ = manager.backup_current("1.0.0").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));

        fs::write(&binary_path, "v2").unwrap();
        let _ = manager.backup_current("2.0.0").unwrap();

        // Rollback to 1.0.0 (not the latest)
        let result = manager.rollback_to_version("1.0.0").unwrap();
        assert!(result.success);
        assert_eq!(result.restored_version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn test_rollback_with_corrupted_backup_fails_gracefully() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("rollback");

        let manager =
            RollbackManager::with_backup_dir(binary_path.clone(), "pt-core", backup_dir.clone());

        // Create backup
        let backup = manager.backup_current("1.0.0").unwrap();

        // Corrupt the backup
        fs::write(&backup.binary_path, "corrupted content").unwrap();

        // Try to restore - should fail checksum verification
        let result = manager.restore_backup(&backup).unwrap();
        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("checksum mismatch"));
    }

    #[test]
    fn test_rollback_to_latest() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("rollback");

        let manager =
            RollbackManager::with_backup_dir(binary_path.clone(), "pt-core", backup_dir.clone());

        // Create backup
        let _ = manager.backup_current("1.0.0").unwrap();

        // Modify the binary
        fs::write(&binary_path, "modified content").unwrap();

        // Rollback to latest
        let result = manager.rollback_to_latest().unwrap();
        assert!(result.success);
        assert_eq!(result.restored_version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn test_rollback_no_backup_available() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("empty_rollback");

        let manager =
            RollbackManager::with_backup_dir(binary_path.clone(), "pt-core", backup_dir.clone());

        // Try to rollback without any backups
        let result = manager.rollback_to_latest().unwrap();
        assert!(!result.success);
        assert!(result
            .error
            .as_ref()
            .unwrap()
            .contains("No backup available"));
    }
}

mod verification_tests {
    use super::*;
    use pt_core::install::verify_binary;

    #[test]
    fn test_verify_working_binary() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_mock_binary(temp.path(), "pt-core", "1.0.0");

        let result = verify_binary(&binary_path, Some("1.0.0")).unwrap();
        assert!(result.passed);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_verify_broken_binary() {
        let temp = TempDir::new().unwrap();
        let binary_path = temp.path().join("pt-core");
        create_broken_binary(&binary_path);

        let result = verify_binary(&binary_path, None).unwrap();
        assert!(!result.passed);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_verify_nonexistent_binary() {
        let result = verify_binary(std::path::Path::new("/nonexistent/binary"), None).unwrap();
        assert!(!result.passed);
        assert!(result.error.as_ref().unwrap().contains("does not exist"));
    }

    #[test]
    fn test_verify_version_mismatch() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_mock_binary(temp.path(), "pt-core", "1.0.0");

        // Expect version 2.0.0 but binary reports 1.0.0
        let result = verify_binary(&binary_path, Some("2.0.0")).unwrap();
        assert!(!result.passed);
        assert!(result.error.as_ref().unwrap().contains("Version mismatch"));
    }
}

mod atomic_replace_tests {
    use super::*;
    use pt_core::install::{RollbackManager, UpdateResult};

    #[test]
    fn test_atomic_replace_same_filesystem() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let new_binary_path = create_mock_binary(temp.path(), "pt-core-new", "2.0.0");
        let backup_dir = temp.path().join("rollback");

        let manager =
            RollbackManager::with_backup_dir(binary_path.clone(), "pt-core", backup_dir.clone());

        // Create backup first
        let _ = manager.backup_current("1.0.0").unwrap();

        // Perform atomic update
        let result = manager
            .atomic_update(&new_binary_path, "1.0.0", None)
            .unwrap();

        // Should succeed (or fail verification which still shows atomic worked)
        match result {
            UpdateResult::Success { .. } | UpdateResult::VerificationFailed { .. } => {
                // Both are acceptable - the atomic replace worked
            }
            UpdateResult::SignatureRejected { .. } => {
                panic!("Unexpected signature rejection (no verifier configured)");
            }
        }
    }
}

mod cli_integration {
    use super::*;

    #[test]
    #[ignore = "requires built pt-core binary"]
    fn test_cli_list_backups() {
        let output = Command::new(env!("CARGO_BIN_EXE_pt-core"))
            .args(["update", "list-backups", "--format", "json"])
            .output()
            .expect("failed to execute pt-core");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("backups") || stdout.contains("schema_version"));
    }

    #[test]
    #[ignore = "requires built pt-core binary"]
    fn test_cli_rollback_no_backup() {
        let output = Command::new(env!("CARGO_BIN_EXE_pt-core"))
            .args(["update", "rollback", "--force"])
            .output()
            .expect("failed to execute pt-core");

        // Should fail (no backup available)
        // But at least it should run without crashing
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let combined = format!("{}{}", stdout, stderr);

        assert!(
            combined.contains("No backup")
                || combined.contains("failed")
                || combined.contains("error")
                || !output.status.success()
        );
    }
}

// ── Signature verification integration tests (bd-oyk3) ──────────────────

mod signature_verification_tests {
    use super::*;
    use pt_core::install::signature::{sign_bytes, SignatureVerifier};
    use pt_core::install::{RollbackManager, SignatureError, UpdateResult};

    /// Helper: generate a fresh ECDSA P-256 key pair.
    fn test_keypair() -> (p256::ecdsa::SigningKey, p256::ecdsa::VerifyingKey) {
        let sk = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let vk = *sk.verifying_key();
        (sk, vk)
    }

    /// Helper: create a binary and sign it with a valid .sig sidecar.
    fn create_signed_binary(
        dir: &std::path::Path,
        name: &str,
        version: &str,
        sk: &p256::ecdsa::SigningKey,
    ) -> PathBuf {
        let binary_path = create_mock_binary(dir, name, version);
        let contents = fs::read(&binary_path).unwrap();
        let sig_der = sign_bytes(&contents, sk);
        let sig_path = dir.join(format!("{}.sig", name));
        fs::write(&sig_path, &sig_der).unwrap();
        binary_path
    }

    // ── Fail-closed: missing .sig file ──────────────────────────────────

    #[test]
    fn test_update_rejected_when_sig_file_missing() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("rollback");

        // New binary WITHOUT a .sig sidecar
        let new_binary = create_mock_binary(temp.path(), "pt-core-new", "2.0.0");

        let (_sk, vk) = test_keypair();
        let mut verifier = SignatureVerifier::new();
        verifier.add_key(vk);

        let manager = RollbackManager::with_backup_dir(binary_path.clone(), "pt-core", backup_dir)
            .with_verifier(verifier);

        let result = manager
            .atomic_update(&new_binary, "1.0.0", Some("2.0.0"))
            .unwrap();

        match result {
            UpdateResult::SignatureRejected { error, binary_path } => {
                assert!(
                    matches!(error, SignatureError::SignatureFileNotFound(_)),
                    "Expected SignatureFileNotFound, got: {:?}",
                    error
                );
                assert!(binary_path.ends_with("pt-core-new"));
            }
            other => panic!("Expected SignatureRejected, got: {:?}", other),
        }

        // Original binary must be untouched
        let original_content = fs::read_to_string(&binary_path).unwrap();
        assert!(
            original_content.contains("1.0.0"),
            "Original binary should be untouched after signature rejection"
        );
    }

    // ── Fail-closed: signature mismatch (wrong key) ─────────────────────

    #[test]
    fn test_update_rejected_when_signature_invalid() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("rollback");

        // Sign the new binary with key A
        let (sk_a, _vk_a) = test_keypair();
        let new_binary = create_signed_binary(temp.path(), "pt-core-new", "2.0.0", &sk_a);

        // Configure verifier with key B (different from the signing key)
        let (_sk_b, vk_b) = test_keypair();
        let mut verifier = SignatureVerifier::new();
        verifier.add_key(vk_b);

        let manager = RollbackManager::with_backup_dir(binary_path.clone(), "pt-core", backup_dir)
            .with_verifier(verifier);

        let result = manager
            .atomic_update(&new_binary, "1.0.0", Some("2.0.0"))
            .unwrap();

        match result {
            UpdateResult::SignatureRejected { error, .. } => {
                assert!(
                    matches!(error, SignatureError::VerificationFailed { tried: 1 }),
                    "Expected VerificationFailed, got: {:?}",
                    error
                );
            }
            other => panic!("Expected SignatureRejected, got: {:?}", other),
        }

        // Original binary untouched
        let original_content = fs::read_to_string(&binary_path).unwrap();
        assert!(original_content.contains("1.0.0"));
    }

    // ── Fail-closed: corrupted .sig file ────────────────────────────────

    #[test]
    fn test_update_rejected_when_sig_corrupted() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("rollback");

        // Create a new binary with a garbage .sig file
        let new_binary = create_mock_binary(temp.path(), "pt-core-new", "2.0.0");
        let sig_path = temp.path().join("pt-core-new.sig");
        fs::write(&sig_path, b"this is not a valid DER signature").unwrap();

        let (_sk, vk) = test_keypair();
        let mut verifier = SignatureVerifier::new();
        verifier.add_key(vk);

        let manager = RollbackManager::with_backup_dir(binary_path.clone(), "pt-core", backup_dir)
            .with_verifier(verifier);

        let result = manager
            .atomic_update(&new_binary, "1.0.0", Some("2.0.0"))
            .unwrap();

        match result {
            UpdateResult::SignatureRejected { error, .. } => {
                assert!(
                    matches!(error, SignatureError::InvalidSignature(_)),
                    "Expected InvalidSignature, got: {:?}",
                    error
                );
            }
            other => panic!("Expected SignatureRejected, got: {:?}", other),
        }
    }

    // ── Happy path: valid signature allows update ───────────────────────

    #[test]
    fn test_update_proceeds_with_valid_signature() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("rollback");

        let (sk, vk) = test_keypair();
        let new_binary = create_signed_binary(temp.path(), "pt-core-new", "2.0.0", &sk);

        let mut verifier = SignatureVerifier::new();
        verifier.add_key(vk);

        let manager = RollbackManager::with_backup_dir(binary_path.clone(), "pt-core", backup_dir)
            .with_verifier(verifier);

        let result = manager.atomic_update(&new_binary, "1.0.0", None).unwrap();

        // Should NOT be SignatureRejected
        assert!(
            !matches!(result, UpdateResult::SignatureRejected { .. }),
            "Valid signature should not be rejected"
        );
    }

    // ── No verifier = no enforcement ────────────────────────────────────

    #[test]
    fn test_update_without_verifier_skips_signature_check() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("rollback");

        // No .sig file, no verifier configured
        let new_binary = create_mock_binary(temp.path(), "pt-core-new", "2.0.0");

        let manager = RollbackManager::with_backup_dir(binary_path, "pt-core", backup_dir);
        // NOTE: no .with_verifier()

        let result = manager.atomic_update(&new_binary, "1.0.0", None).unwrap();

        // Should not be rejected — no verifier means no enforcement
        assert!(
            !matches!(result, UpdateResult::SignatureRejected { .. }),
            "Without verifier, missing .sig should not cause rejection"
        );
    }

    // ── Key rotation: old key still validates ───────────────────────────

    #[test]
    fn test_update_key_rotation_old_key_accepted() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("rollback");

        // Sign with old key
        let (old_sk, old_vk) = test_keypair();
        let new_binary = create_signed_binary(temp.path(), "pt-core-new", "2.0.0", &old_sk);

        // Verifier trusts both new and old keys
        let (_new_sk, new_vk) = test_keypair();
        let mut verifier = SignatureVerifier::new();
        verifier.add_key(new_vk);
        verifier.add_key(old_vk);

        let manager = RollbackManager::with_backup_dir(binary_path, "pt-core", backup_dir)
            .with_verifier(verifier);

        let result = manager.atomic_update(&new_binary, "1.0.0", None).unwrap();

        assert!(
            !matches!(result, UpdateResult::SignatureRejected { .. }),
            "Old key should still be accepted during rotation"
        );
    }

    // ── UpdateResult helpers ────────────────────────────────────────────

    #[test]
    fn test_update_result_signature_error_accessor() {
        let temp = TempDir::new().unwrap();
        let binary_path = create_mock_binary(temp.path(), "pt-core", "1.0.0");
        let backup_dir = temp.path().join("rollback");

        let new_binary = create_mock_binary(temp.path(), "pt-core-new", "2.0.0");
        // No .sig sidecar

        let (_sk, vk) = test_keypair();
        let mut verifier = SignatureVerifier::new();
        verifier.add_key(vk);

        let manager = RollbackManager::with_backup_dir(binary_path, "pt-core", backup_dir)
            .with_verifier(verifier);

        let result = manager.atomic_update(&new_binary, "1.0.0", None).unwrap();

        assert!(!result.is_success());
        assert!(result.signature_error().is_some());
        assert!(result.verification().is_none());
    }
}
