//! E2E tests for bundle encryption + verification flows (bd-3k9b).
//!
//! Validates:
//! - Encrypted bundles decrypt with correct passphrase only
//! - Verification detects corruption
//! - Failure paths produce clear errors
//! - JSONL logs emitted per case
//! - No raw secrets leak through encryption/decryption cycle

use pt_bundle::{BundleError, BundleReader, BundleWriter, BUNDLE_SCHEMA_VERSION};
use pt_redact::{ExportProfile, RedactionPolicy};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read, Write};
use tempfile::TempDir;
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

// ============================================================================
// Helpers
// ============================================================================

/// Build an archive fixture; opaque bytes require explicit Forensic export.
fn build_test_bundle() -> (Vec<u8>, pt_bundle::BundleManifest) {
    let mut writer = BundleWriter::new(
        "pt-20260205-enc-test",
        "host-enc-test",
        ExportProfile::Forensic,
    )
    .with_pt_version("2.0.0-test")
    .with_redaction_policy("1.0.0", "sha256-test-key")
    .with_description("Encryption + verification E2E test");

    writer
        .add_summary(&json!({
            "total_processes": 100,
            "candidates": 4,
            "kills": 1,
            "spares": 3,
        }))
        .expect("add summary");

    writer
        .add_plan(&json!({
            "recommendations": [
                {"pid": 1234, "action": "kill", "confidence": 0.99},
                {"pid": 5678, "action": "spare", "confidence": 0.60}
            ]
        }))
        .expect("add plan");

    writer.add_telemetry("audit", vec![0x50, 0x41, 0x52, 0x31, 0xAA, 0xBB]);
    writer.add_telemetry("proc_samples", vec![0x50, 0x41, 0x52, 0x31, 0xCC, 0xDD]);

    let log_entry = json!({
        "event": "enc_e2e_test",
        "timestamp": "2026-02-05T12:00:00Z",
        "phase": "bundle",
        "case_id": "enc-1",
        "command": "pt bundle create --encrypt",
        "exit_code": 0,
        "duration_ms": 50,
        "artifacts": [
            {"path": "telemetry/audit.parquet", "kind": "parquet"},
            {"path": "telemetry/proc_samples.parquet", "kind": "parquet"}
        ]
    });
    writer.add_log("events", format!("{}\n", log_entry).into_bytes());

    writer.write_to_vec().expect("write bundle")
}

// ============================================================================
// Encryption: Correct Passphrase Roundtrip
// ============================================================================

#[test]
fn test_encrypt_decrypt_roundtrip_preserves_all_content() {
    let temp_dir = TempDir::new().expect("temp dir");
    let passphrase = "correct-horse-battery-staple";

    let bundle_path = temp_dir.path().join("session.ptb");

    // Write encrypted bundle directly via BundleWriter
    let mut writer = BundleWriter::new(
        "pt-20260205-enc-test",
        "host-enc-test",
        ExportProfile::Forensic,
    )
    .with_pt_version("2.0.0-test")
    .with_redaction_policy("1.0.0", "sha256-test-key");

    writer
        .add_summary(&json!({"total_processes": 100, "candidates": 4}))
        .expect("add summary");
    writer.add_telemetry("audit", vec![0x50, 0x41, 0x52, 0x31]);

    let manifest = writer
        .write_encrypted(&bundle_path, passphrase)
        .expect("write encrypted");

    // File should exist and not look like a ZIP
    let raw = std::fs::read(&bundle_path).expect("read raw");
    assert_ne!(&raw[0..2], b"PK", "Encrypted file should not be a raw ZIP");

    // Open with correct passphrase
    let mut reader =
        BundleReader::open_with_passphrase(&bundle_path, Some(passphrase)).expect("open");
    assert_eq!(reader.session_id(), "pt-20260205-enc-test");
    assert_eq!(reader.export_profile(), ExportProfile::Forensic);

    // Verify all files intact
    let failures = reader.verify_all();
    assert!(
        failures.is_empty(),
        "Encrypted roundtrip verification failed: {:?}",
        failures
    );

    // Read summary to confirm content preserved
    let summary: serde_json::Value = reader.read_summary().expect("read summary");
    assert_eq!(summary["total_processes"], 100);
    assert_eq!(summary["candidates"], 4);
    assert_eq!(
        reader
            .read_verified("telemetry/audit.parquet")
            .expect("read opaque archive payload"),
        vec![0x50, 0x41, 0x52, 0x31]
    );

    eprintln!(
        "[INFO] Encrypted roundtrip: {} files, {} raw bytes",
        manifest.file_count(),
        raw.len()
    );
}

#[test]
fn test_encrypt_decrypt_with_various_passphrases() {
    let long_passphrase = "a".repeat(256);
    let passphrases: Vec<&str> = vec![
        "simple",
        "correct horse battery staple",
        "P@$$w0rd!#%^&*()",
        "日本語パスフレーズ",
        &long_passphrase,
    ];

    for passphrase in &passphrases {
        let temp_dir = TempDir::new().expect("temp dir");
        let bundle_path = temp_dir.path().join("session.ptb");

        let mut writer =
            BundleWriter::new("pt-20261004-120100-abcd", "host-pp", ExportProfile::Safe);
        writer
            .add_summary(&json!({"test": "passphrase"}))
            .expect("add summary");

        writer
            .write_encrypted(&bundle_path, passphrase)
            .expect("write encrypted");

        let mut reader =
            BundleReader::open_with_passphrase(&bundle_path, Some(passphrase)).expect("open");
        assert_eq!(reader.session_id(), "pt-20261004-120100-abcd");
        let failures = reader.verify_all();
        assert!(
            failures.is_empty(),
            "Passphrase {:?}: verification failed",
            &passphrase[..passphrase.len().min(20)]
        );
    }

    eprintln!("[INFO] Tested {} different passphrases", passphrases.len());
}

#[test]
fn test_encrypted_bundle_all_profiles() {
    let profiles = [
        ExportProfile::Minimal,
        ExportProfile::Safe,
        ExportProfile::Forensic,
    ];
    let passphrase = "profile-test-key";

    for profile in profiles {
        let temp_dir = TempDir::new().expect("temp dir");
        let bundle_path = temp_dir.path().join("session.ptb");

        let mut writer = BundleWriter::new("pt-20261004-120200-abcd", "host-prof", profile);
        writer
            .add_summary(&json!({"total_processes": 8, "candidates": 2}))
            .expect("add summary");
        writer
            .add_plan(&json!({"recommendations": [{"pid": 5678, "action": "spare"}]}))
            .expect("add plan");
        writer.add_log(
            "events",
            b"{\"event\":\"profile_test\",\"exit_code\":0}\n".to_vec(),
        );

        let manifest = writer
            .write_encrypted(&bundle_path, passphrase)
            .expect("write encrypted");

        let mut reader =
            BundleReader::open_with_passphrase(&bundle_path, Some(passphrase)).expect("open");
        assert_eq!(reader.export_profile(), profile);
        assert_eq!(reader.session_id(), "pt-20261004-120200-abcd");
        let summary: serde_json::Value = reader.read_summary().expect("read summary");
        assert_eq!(summary, json!({"total_processes": 8, "candidates": 2}));
        if profile == ExportProfile::Minimal {
            assert_eq!(manifest.file_count(), 1);
            assert!(!reader.has_file("plan.json"));
            assert!(!reader.has_file("logs/events.jsonl"));
        } else {
            assert_eq!(manifest.file_count(), 3);
            let plan: serde_json::Value = reader.read_plan().expect("read plan").expect("plan");
            assert_eq!(plan["recommendations"][0]["action"], "spare");
            assert!(reader.has_file("logs/events.jsonl"));
        }

        let failures = reader.verify_all();
        assert!(
            failures.is_empty(),
            "Profile {:?}: encrypted verification failed: {:?}",
            profile,
            failures
        );

        eprintln!(
            "[INFO] Profile {:?}: encrypted, {} files, version={}",
            profile,
            manifest.file_count(),
            manifest.bundle_version
        );
    }
}

// ============================================================================
// Encryption: Wrong Passphrase Rejection
// ============================================================================

#[test]
fn test_wrong_passphrase_fails_with_clear_error() {
    let temp_dir = TempDir::new().expect("temp dir");
    let bundle_path = temp_dir.path().join("session.ptb");

    let mut writer = BundleWriter::new("session-wrong", "host-wrong", ExportProfile::Safe);
    writer
        .add_summary(&json!({"test": true}))
        .expect("add summary");
    writer
        .write_encrypted(&bundle_path, "correct-key")
        .expect("write encrypted");

    let result = BundleReader::open_with_passphrase(&bundle_path, Some("wrong-key"));
    match result {
        Err(BundleError::DecryptionFailed) => {} // expected
        Err(other) => panic!("Expected DecryptionFailed, got: {}", other),
        Ok(_) => panic!("Expected error, but open succeeded"),
    }
}

#[test]
fn test_no_passphrase_on_encrypted_bundle_fails() {
    let temp_dir = TempDir::new().expect("temp dir");
    let bundle_path = temp_dir.path().join("session.ptb");

    let mut writer = BundleWriter::new("session-nopass", "host-nopass", ExportProfile::Safe);
    writer
        .add_summary(&json!({"test": true}))
        .expect("add summary");
    writer
        .write_encrypted(&bundle_path, "my-key")
        .expect("write encrypted");

    // Opening without passphrase via `open`
    let result = BundleReader::open(&bundle_path);
    match result {
        Err(BundleError::EncryptedBundleRequiresPassphrase) => {} // expected
        Err(other) => panic!("Expected EncryptedBundleRequiresPassphrase, got: {}", other),
        Ok(_) => panic!("Expected error, but open succeeded"),
    }
}

#[test]
fn test_none_passphrase_on_encrypted_bundle_fails() {
    let temp_dir = TempDir::new().expect("temp dir");
    let bundle_path = temp_dir.path().join("session.ptb");

    let mut writer = BundleWriter::new("session-none", "host-none", ExportProfile::Safe);
    writer
        .add_summary(&json!({"test": true}))
        .expect("add summary");
    writer
        .write_encrypted(&bundle_path, "my-key")
        .expect("write encrypted");

    // Opening with None passphrase via `open_with_passphrase`
    let result = BundleReader::open_with_passphrase(&bundle_path, None);
    match result {
        Err(BundleError::EncryptedBundleRequiresPassphrase) => {} // expected
        Err(other) => panic!("Expected EncryptedBundleRequiresPassphrase, got: {}", other),
        Ok(_) => panic!("Expected error, but open succeeded"),
    }
}

// ============================================================================
// Verification: Corruption Detection
// ============================================================================

#[test]
fn test_corrupted_bundle_bytes_detected() {
    let (mut bytes, _) = build_test_bundle();

    // Corrupt the middle of the ZIP — this may corrupt file data inside
    // rather than the ZIP directory (which lives at the end).
    // The bundle may still open, but verification should catch corrupted files.
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    bytes[mid + 1] ^= 0xFF;
    bytes[mid + 2] ^= 0xFF;

    match BundleReader::from_bytes(bytes) {
        Err(_) => {
            // Corruption prevented opening entirely — good
        }
        Ok(mut reader) => {
            // Opened but verification should catch data corruption
            let failures = reader.verify_all();
            assert!(
                !failures.is_empty(),
                "Corrupted bundle opened but verify_all should detect corruption"
            );
            eprintln!(
                "[INFO] Corruption detected during verification: {:?}",
                failures
            );
        }
    }
}

#[test]
fn test_truncated_bundle_detected() {
    let (bytes, _) = build_test_bundle();

    // Truncate to just 100 bytes
    let truncated = bytes[..100].to_vec();
    let result = BundleReader::from_bytes(truncated);
    assert!(result.is_err(), "Truncated bundle should fail to open");
}

#[test]
fn test_corrupted_encrypted_bundle_detected() {
    let temp_dir = TempDir::new().expect("temp dir");
    let bundle_path = temp_dir.path().join("session.ptb");
    let passphrase = "corruption-test";

    let mut writer = BundleWriter::new("session-corrupt", "host-corrupt", ExportProfile::Safe);
    writer
        .add_summary(&json!({"test": "corruption"}))
        .expect("add summary");
    writer
        .write_encrypted(&bundle_path, passphrase)
        .expect("write encrypted");

    // Read and corrupt the encrypted bytes
    let mut raw = std::fs::read(&bundle_path).expect("read");
    let data_start = 8 + 4 + 16 + 12; // MAGIC + iterations + salt + nonce
    assert!(
        raw.len() > data_start + 10,
        "encrypted payload must be present"
    );
    raw[data_start + 5] ^= 0xFF;
    raw[data_start + 6] ^= 0xFF;
    std::fs::write(&bundle_path, &raw).expect("write corrupted");

    // Should fail with DecryptionFailed (AEAD authentication tag mismatch)
    let result = BundleReader::open_with_passphrase(&bundle_path, Some(passphrase));
    assert!(matches!(result, Err(BundleError::DecryptionFailed)));
}

#[test]
fn test_truncated_encrypted_header_detected() {
    let temp_dir = TempDir::new().expect("temp dir");
    let bundle_path = temp_dir.path().join("session.ptb");
    let passphrase = "truncate-test";

    let mut writer = BundleWriter::new("session-trunc", "host-trunc", ExportProfile::Safe);
    writer
        .add_summary(&json!({"test": "truncate"}))
        .expect("add summary");
    writer
        .write_encrypted(&bundle_path, passphrase)
        .expect("write encrypted");

    // Truncate the encrypted file to just the magic bytes
    let raw = std::fs::read(&bundle_path).expect("read");
    std::fs::write(&bundle_path, &raw[..10]).expect("write truncated");

    let result = BundleReader::open_with_passphrase(&bundle_path, Some(passphrase));
    assert!(result.is_err(), "Truncated encrypted bundle should fail");
}

#[test]
fn test_checksum_verification_detects_tampered_content() {
    let mut writer1 = BundleWriter::new("session-chk1", "host-chk1", ExportProfile::Forensic);
    writer1
        .add_summary(&json!({"test": "checksum1"}))
        .expect("add summary");
    writer1.add_telemetry("audit", vec![1, 2, 3, 4, 5]);

    let (bytes1, manifest1) = writer1.write_to_vec().expect("write bundle1");
    let mut reader1 = BundleReader::from_bytes(bytes1.clone()).expect("open bundle1");

    // All files should verify
    let failures = reader1.verify_all();
    assert!(
        failures.is_empty(),
        "Original bundle should verify: {:?}",
        failures
    );

    // Verify each file has non-empty checksums
    for entry in manifest1.files.iter() {
        assert!(
            !entry.sha256.is_empty(),
            "sha256 should not be empty for {}",
            entry.path
        );
        assert!(entry.bytes > 0, "bytes should be > 0 for {}", entry.path);
    }

    // Rebuild a valid ZIP with changed telemetry and the original manifest.
    // ZIP CRCs stay valid, so rejection must come from the bundle checksum gate.
    let mut original_zip = ZipArchive::new(Cursor::new(bytes1)).expect("open original ZIP");
    let mut tampered_zip = ZipWriter::new(Cursor::new(Vec::new()));
    let options: FileOptions<'_, ()> =
        FileOptions::default().compression_method(CompressionMethod::Deflated);
    let mut changed_payloads = 0;
    for index in 0..original_zip.len() {
        let mut entry = original_zip.by_index(index).expect("ZIP entry");
        let path = entry.name().to_string();
        let mut data = Vec::new();
        entry.read_to_end(&mut data).expect("read ZIP entry");
        if path == "telemetry/audit.parquet" {
            assert_eq!(data, vec![1, 2, 3, 4, 5]);
            data[0] ^= 0xFF;
            changed_payloads += 1;
        }
        tampered_zip
            .start_file(path, options)
            .expect("start ZIP entry");
        tampered_zip.write_all(&data).expect("write ZIP entry");
    }
    assert_eq!(changed_payloads, 1, "must tamper with the named payload");
    let tampered_bytes = tampered_zip
        .finish()
        .expect("finish tampered ZIP")
        .into_inner();
    let mut tampered = BundleReader::from_bytes(tampered_bytes).expect("open valid tampered ZIP");
    assert!(matches!(
        tampered.read_verified("telemetry/audit.parquet"),
        Err(BundleError::ChecksumMismatch { path, .. }) if path == "telemetry/audit.parquet"
    ));
    let failures = tampered.verify_all();
    assert_eq!(failures.len(), 1, "only the changed payload should fail");
    assert_eq!(failures[0], "telemetry/audit.parquet");

    eprintln!(
        "[INFO] Checksum verification: {} files validated",
        manifest1.file_count()
    );
}

// ============================================================================
// Verification: Manifest Integrity
// ============================================================================

#[test]
fn test_manifest_checksums_match_file_content() {
    let (bytes, manifest) = build_test_bundle();
    let mut reader = BundleReader::from_bytes(bytes).expect("open bundle");

    for entry in manifest.files.iter() {
        let data = reader
            .read_verified(&entry.path)
            .unwrap_or_else(|e| panic!("Failed to verify {}: {}", entry.path, e));

        assert_eq!(
            data.len() as u64,
            entry.bytes,
            "Size mismatch for {}",
            entry.path
        );
    }

    eprintln!(
        "[INFO] All {} manifest entries verified",
        manifest.file_count()
    );
}

#[test]
fn test_manifest_version_present_and_valid() {
    let (_, manifest) = build_test_bundle();

    assert_eq!(manifest.bundle_version, BUNDLE_SCHEMA_VERSION);
    assert!(!manifest.bundle_version.is_empty());
    assert!(
        manifest.bundle_version.contains('.'),
        "Version should be semver: {}",
        manifest.bundle_version
    );
}

#[test]
fn test_manifest_redaction_metadata_preserved_through_encryption() {
    let temp_dir = TempDir::new().expect("temp dir");
    let bundle_path = temp_dir.path().join("session.ptb");
    let passphrase = "meta-test";

    let mut writer = BundleWriter::new("session-meta", "host-meta", ExportProfile::Safe)
        .with_redaction_policy("1.0.0", "sha256-abc123");
    writer
        .add_summary(&json!({"test": "metadata"}))
        .expect("add summary");

    let orig_manifest = writer
        .write_encrypted(&bundle_path, passphrase)
        .expect("write encrypted");

    let policy = RedactionPolicy::default();
    let canonical_policy = serde_json::to_value(&policy).expect("policy value");
    let policy_bytes = serde_json::to_vec(&canonical_policy).expect("policy bytes");
    assert_eq!(
        orig_manifest.redaction_policy_version,
        policy.schema_version
    );
    assert_eq!(
        orig_manifest.redaction_policy_hash,
        format!("{:x}", Sha256::digest(&policy_bytes))
    );
    assert_ne!(orig_manifest.redaction_policy_hash, "sha256-abc123");

    let reader = BundleReader::open_with_passphrase(&bundle_path, Some(passphrase)).expect("open");

    assert_eq!(
        reader.manifest().redaction_policy_version,
        orig_manifest.redaction_policy_version
    );
    assert_eq!(
        reader.manifest().redaction_policy_hash,
        orig_manifest.redaction_policy_hash
    );
    assert_eq!(reader.manifest().bundle_version, BUNDLE_SCHEMA_VERSION);
}

// ============================================================================
// Unencrypted Bundle: Passphrase on Non-Encrypted
// ============================================================================

#[test]
fn test_passphrase_on_unencrypted_bundle_still_opens() {
    let temp_dir = TempDir::new().expect("temp dir");
    let bundle_path = temp_dir.path().join("session.ptb");

    let mut writer =
        BundleWriter::new("pt-20261004-120300-abcd", "host-plain", ExportProfile::Safe);
    writer
        .add_summary(&json!({"test": "plain"}))
        .expect("add summary");
    writer.write(&bundle_path).expect("write unencrypted");

    // Opening an unencrypted bundle with a passphrase should still work
    // (passphrase is just ignored since file isn't encrypted)
    let reader = BundleReader::open_with_passphrase(&bundle_path, Some("unnecessary-passphrase"))
        .expect("open plain with passphrase");
    assert_eq!(reader.session_id(), "pt-20261004-120300-abcd");
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_encrypted_empty_bundle_rejected() {
    let temp_dir = TempDir::new().expect("temp dir");
    let bundle_path = temp_dir.path().join("empty.ptb");

    let writer = BundleWriter::new("session-empty-enc", "host-empty", ExportProfile::Safe);
    let result = writer.write_encrypted(&bundle_path, "key");
    assert!(result.is_err(), "Empty encrypted bundle should be rejected");
}

#[test]
fn test_garbage_file_not_recognized_as_encrypted() {
    let temp_dir = TempDir::new().expect("temp dir");
    let bundle_path = temp_dir.path().join("garbage.ptb");

    std::fs::write(&bundle_path, b"this is not a bundle at all").expect("write garbage");

    // Should fail but not with EncryptedBundleRequiresPassphrase
    let result = BundleReader::open(&bundle_path);
    match result {
        Err(BundleError::EncryptedBundleRequiresPassphrase) => {
            panic!("Garbage file should not be detected as encrypted")
        }
        Err(_) => {} // expected — some other error
        Ok(_) => panic!("Garbage file should not parse as valid bundle"),
    }
}

#[test]
fn test_very_small_file_handling() {
    let temp_dir = TempDir::new().expect("temp dir");
    let bundle_path = temp_dir.path().join("tiny.ptb");

    // Write just 2 bytes
    std::fs::write(&bundle_path, b"PK").expect("write tiny");

    let result = BundleReader::open(&bundle_path);
    assert!(
        result.is_err(),
        "2-byte file should not parse as valid bundle"
    );
}

#[test]
fn test_encrypted_bundle_different_sessions_are_independent() {
    let temp_dir = TempDir::new().expect("temp dir");
    let passphrase = "shared-passphrase";

    // Create two encrypted bundles with same passphrase but different content
    for i in 1..=2 {
        let path = temp_dir.path().join(format!("session-{}.ptb", i));
        let mut writer = BundleWriter::new(
            format!("pt-20261004-12040{}-abcd", i),
            "host-ind",
            ExportProfile::Safe,
        );
        writer
            .add_summary(&json!({"total_processes": i}))
            .expect("add summary");
        writer.write_encrypted(&path, passphrase).expect("write");
    }

    // Each should decrypt independently with correct content
    let mut reader1 = BundleReader::open_with_passphrase(
        &temp_dir.path().join("session-1.ptb"),
        Some(passphrase),
    )
    .expect("open 1");
    let mut reader2 = BundleReader::open_with_passphrase(
        &temp_dir.path().join("session-2.ptb"),
        Some(passphrase),
    )
    .expect("open 2");

    assert_eq!(reader1.session_id(), "pt-20261004-120401-abcd");
    assert_eq!(reader2.session_id(), "pt-20261004-120402-abcd");

    let sum1: serde_json::Value = reader1.read_summary().expect("read 1");
    let sum2: serde_json::Value = reader2.read_summary().expect("read 2");
    assert_eq!(sum1["total_processes"], 1);
    assert_eq!(sum2["total_processes"], 2);
}

// ============================================================================
// JSONL Log Schema Validation Through Bundle
// ============================================================================

#[test]
fn test_encrypted_bundle_preserves_jsonl_log_schema() {
    let temp_dir = TempDir::new().expect("temp dir");
    let bundle_path = temp_dir.path().join("session.ptb");
    let passphrase = "log-schema-test";

    let (plain_bytes, _) = build_test_bundle();

    // Manually encrypt the plain bytes
    let encrypted =
        pt_bundle::encryption::encrypt_bytes(&plain_bytes, passphrase).expect("encrypt");
    std::fs::write(&bundle_path, &encrypted).expect("write");

    let mut reader =
        BundleReader::open_with_passphrase(&bundle_path, Some(passphrase)).expect("open");

    let log_bytes = reader.read_verified("logs/events.jsonl").expect("read log");
    let log_text = String::from_utf8(log_bytes).expect("utf8");

    let required_fields = [
        "event",
        "timestamp",
        "phase",
        "case_id",
        "command",
        "exit_code",
        "duration_ms",
        "artifacts",
    ];

    for line in log_text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let obj: serde_json::Value = serde_json::from_str(line).expect("parse JSONL line");
        let map = obj.as_object().expect("JSONL line should be object");

        for field in &required_fields {
            assert!(
                map.contains_key(*field),
                "JSONL line missing required field '{}': {}",
                field,
                line
            );
        }

        // Validate artifacts is an array of objects with path + kind
        if let Some(artifacts) = map.get("artifacts").and_then(|v| v.as_array()) {
            for (i, artifact) in artifacts.iter().enumerate() {
                let a = artifact
                    .as_object()
                    .unwrap_or_else(|| panic!("artifact[{}] should be object", i));
                assert!(a.contains_key("path"), "artifact[{}] missing 'path'", i);
                assert!(a.contains_key("kind"), "artifact[{}] missing 'kind'", i);
            }
        }
    }

    eprintln!("[INFO] JSONL schema validated through encrypted bundle");
}

// ============================================================================
// Secret Leak Prevention Through Encryption Cycle
// ============================================================================

#[test]
fn test_no_secrets_leak_through_encrypted_bundle_cycle() {
    let temp_dir = TempDir::new().expect("temp dir");
    let passphrase = "secret-leak-test";
    let canary_secret = "AKIAIOSFODNN7EXAMPLE";

    // Check the redactor, then submit the raw secret to the writer itself.
    let policy = pt_redact::RedactionPolicy::default();
    let key = pt_redact::KeyMaterial::from_bytes([42u8; 32], "enc-leak-test");
    let engine = pt_redact::RedactionEngine::with_key(policy, key);
    let redacted = engine.redact_with_profile(
        canary_secret,
        pt_redact::FieldClass::FreeText,
        ExportProfile::Safe,
    );

    assert!(
        !redacted.output.contains(canary_secret),
        "Redaction should have scrubbed the secret"
    );

    let bundle_path = temp_dir.path().join("session.ptb");
    let mut writer = BundleWriter::new("session-leak", "host-leak", ExportProfile::Safe)
        .with_redaction_engine(engine)
        .with_description(canary_secret);
    writer
        .add_summary(&json!({
            "note": canary_secret,
            "test": "secret-leak",
        }))
        .expect("add summary");

    writer
        .write_encrypted(&bundle_path, passphrase)
        .expect("write encrypted");

    // The raw encrypted file should not contain the secret either
    let raw_bytes = std::fs::read(&bundle_path).expect("read raw");
    let raw_text = String::from_utf8_lossy(&raw_bytes);
    assert!(
        !raw_text.contains(canary_secret),
        "Raw encrypted file should not contain canary secret"
    );

    // Decrypted content should not contain the secret
    let mut reader =
        BundleReader::open_with_passphrase(&bundle_path, Some(passphrase)).expect("open");
    let manifest_text = reader.manifest().to_json().expect("manifest JSON");
    assert!(
        !manifest_text.contains(canary_secret),
        "manifest leaked secret"
    );
    let summary_bytes = reader.read_verified("summary.json").expect("read summary");
    let summary_text = String::from_utf8(summary_bytes).expect("utf8");
    assert!(
        !summary_text.contains(canary_secret),
        "Decrypted summary should not contain canary secret"
    );
}

#[test]
fn test_safe_opaque_payload_refused_before_encrypted_destination_creation() {
    let temp_dir = TempDir::new().expect("temp dir");
    let bundle_path = temp_dir.path().join("refused-encrypted.ptb");
    let mut writer = BundleWriter::new("session-refused", "host-refused", ExportProfile::Safe);
    writer
        .add_summary(&json!({"total_processes": 1}))
        .expect("add summary");
    writer.add_telemetry("audit", b"opaque private telemetry".to_vec());

    let result = writer.write_encrypted(&bundle_path, "refusal-test-key");
    assert!(matches!(
        result,
        Err(BundleError::UnsanitizedPayload { path, profile })
            if path == "telemetry/audit.parquet" && profile == "safe"
    ));
    assert!(!bundle_path.exists(), "refusal must not create an output");
}
