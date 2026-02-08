//! Session snapshot persistence with schema validation, redaction, and integrity.
//!
//! Provides atomic writes of individual session artifacts (inventory, inference,
//! plan) and validated reads with version compatibility checks.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::{SessionError, SessionHandle, SNAPSHOT_SCHEMA_VERSION};

/// Subdirectory names for artifact types.
const INVENTORY_FILE: &str = "scan/inventory.json";
const INFERENCE_FILE: &str = "inference/results.json";
const PLAN_FILE: &str = "decision/plan.json";
const META_FILE: &str = "run_metadata.json";

/// Redaction sentinel for sensitive strings.
const REDACTED: &str = "<REDACTED>";

/// SHA-256 hex digest length.
const SHA256_HEX_LEN: usize = 64;

// ---------------------------------------------------------------------------
// Artifact envelope
// ---------------------------------------------------------------------------

/// Versioned envelope wrapping any persisted artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactEnvelope<T> {
    /// Schema version for forward/backward compat checks.
    pub schema_version: String,
    /// Session that produced this artifact.
    pub session_id: String,
    /// RFC-3339 timestamp of artifact creation.
    pub generated_at: String,
    /// Host that produced the artifact.
    pub host_id: String,
    /// SHA-256 hex digest of the inner payload JSON.
    pub integrity_sha256: String,
    /// The actual payload.
    pub payload: T,
}

impl<T: Serialize> ArtifactEnvelope<T> {
    /// Create a new envelope with integrity computed at persistence time.
    pub fn new(session_id: &str, host_id: &str, payload: T) -> Self {
        Self {
            schema_version: SNAPSHOT_SCHEMA_VERSION.to_string(),
            session_id: session_id.to_string(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            host_id: host_id.to_string(),
            integrity_sha256: String::new(),
            payload,
        }
    }
}

// ---------------------------------------------------------------------------
// Inventory artifact
// ---------------------------------------------------------------------------

/// Persisted process identity record (redaction-safe).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PersistedProcess {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub start_id: String,
    /// Display command (may be redacted).
    pub comm: String,
    /// Full command line (may be redacted).
    pub cmd: String,
    pub state: String,
    pub start_time_unix: i64,
    pub elapsed_secs: u64,
    /// Identity quality tag for revalidation safety.
    pub identity_quality: String,
}

/// Inventory artifact: all scanned processes for the session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryArtifact {
    pub total_system_processes: u64,
    pub protected_filtered: u64,
    pub record_count: usize,
    pub records: Vec<PersistedProcess>,
}

// ---------------------------------------------------------------------------
// Inference artifact
// ---------------------------------------------------------------------------

/// Persisted inference result for one process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PersistedInference {
    pub pid: u32,
    pub start_id: String,
    pub classification: String,
    pub posterior_useful: f64,
    pub posterior_useful_bad: f64,
    pub posterior_abandoned: f64,
    pub posterior_zombie: f64,
    pub confidence: String,
    pub recommended_action: String,
    pub score: u32,
}

/// Inference artifact: inference results for all candidates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceArtifact {
    pub candidate_count: usize,
    pub candidates: Vec<PersistedInference>,
}

// ---------------------------------------------------------------------------
// Plan artifact
// ---------------------------------------------------------------------------

/// Persisted plan action for one process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PersistedPlanAction {
    pub pid: u32,
    pub start_id: String,
    pub action: String,
    pub expected_loss: f64,
    pub rationale: String,
}

/// Plan artifact: the generated action plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanArtifact {
    pub action_count: usize,
    pub kill_count: usize,
    pub review_count: usize,
    pub spare_count: usize,
    pub actions: Vec<PersistedPlanAction>,
}

// ---------------------------------------------------------------------------
// Run metadata
// ---------------------------------------------------------------------------

/// Run metadata capturing tool versions, config hashes, and host info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMetadata {
    pub pt_version: String,
    pub schema_version: String,
    pub host_id: String,
    pub hostname: String,
    pub os_family: String,
    pub os_arch: String,
    pub cores: u32,
    pub memory_total_gb: f64,
    /// SHA-256 of the active priors config.
    pub priors_hash: String,
    /// SHA-256 of the active policy config.
    pub policy_hash: String,
    /// Arbitrary extra tags for provenance.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/// Redaction policy for snapshot persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RedactionPolicy {
    /// Keep all strings as-is (for local-only storage).
    None,
    /// Redact command lines that match sensitive patterns.
    #[default]
    Standard,
    /// Redact all command lines unconditionally.
    Full,
}

/// Sensitive substrings that trigger redaction under `Standard` policy.
const SENSITIVE_PATTERNS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "aws_secret",
    "private_key",
    "credential",
    "auth_token",
    "bearer ",
    "-----begin",
];

/// Apply redaction policy to a command string.
pub fn redact_cmd(cmd: &str, policy: RedactionPolicy) -> String {
    match policy {
        RedactionPolicy::None => cmd.to_string(),
        RedactionPolicy::Full => REDACTED.to_string(),
        RedactionPolicy::Standard => {
            let lower = cmd.to_lowercase();
            if SENSITIVE_PATTERNS.iter().any(|p| lower.contains(p)) {
                REDACTED.to_string()
            } else {
                cmd.to_string()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Persist / load helpers
// ---------------------------------------------------------------------------

/// Persist an artifact envelope atomically to a file inside a session dir.
fn persist_artifact<T: serde::de::DeserializeOwned + Serialize>(
    handle: &SessionHandle,
    rel_path: &str,
    mut envelope: ArtifactEnvelope<T>,
) -> Result<PathBuf, SessionError> {
    let path = handle.dir.join(rel_path);
    envelope.integrity_sha256 = payload_sha256(&envelope.payload, &path)?;
    super::write_json_pretty_atomic(&path, &envelope)?;
    Ok(path)
}

/// Load and validate an artifact envelope from a session directory.
fn load_artifact<T: serde::de::DeserializeOwned + Serialize>(
    handle: &SessionHandle,
    rel_path: &str,
) -> Result<ArtifactEnvelope<T>, SessionError> {
    let path = handle.dir.join(rel_path);
    let content = std::fs::read_to_string(&path).map_err(|e| SessionError::Io {
        path: path.clone(),
        source: e,
    })?;
    let envelope: ArtifactEnvelope<T> =
        serde_json::from_str(&content).map_err(|e| SessionError::Json {
            path: path.clone(),
            source: e,
        })?;

    // Validate schema version compatibility.
    if !pt_common::schema::is_compatible(&envelope.schema_version) {
        return Err(SessionError::Json {
            path: path.clone(),
            source: serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "incompatible schema version: {} (expected {})",
                    envelope.schema_version, SNAPSHOT_SCHEMA_VERSION
                ),
            )),
        });
    }

    // Validate integrity hash.
    let payload_json = canonical_payload_bytes(&envelope.payload, &path)?;
    let computed = sha256_hex(&payload_json);
    if computed != envelope.integrity_sha256 {
        return Err(SessionError::Json {
            path,
            source: serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "integrity check failed: payload SHA-256 mismatch",
            )),
        });
    }

    Ok(envelope)
}

/// Load an artifact envelope but skip integrity validation.
///
/// Useful as a compatibility escape hatch while evolving persistence formats.
fn load_artifact_unchecked<T: serde::de::DeserializeOwned + Serialize>(
    handle: &SessionHandle,
    rel_path: &str,
) -> Result<ArtifactEnvelope<T>, SessionError> {
    let path = handle.dir.join(rel_path);
    let content = std::fs::read_to_string(&path).map_err(|e| SessionError::Io {
        path: path.clone(),
        source: e,
    })?;
    let envelope: ArtifactEnvelope<T> =
        serde_json::from_str(&content).map_err(|e| SessionError::Json {
            path: path.clone(),
            source: e,
        })?;

    // Validate schema version compatibility.
    if !pt_common::schema::is_compatible(&envelope.schema_version) {
        return Err(SessionError::Json {
            path: path.clone(),
            source: serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "incompatible schema version: {} (expected {})",
                    envelope.schema_version, SNAPSHOT_SCHEMA_VERSION
                ),
            )),
        });
    }

    Ok(envelope)
}

fn payload_sha256<T: serde::de::DeserializeOwned + Serialize>(
    payload: &T,
    path: &Path,
) -> Result<String, SessionError> {
    let payload_json = canonical_payload_bytes(payload, path)?;
    Ok(sha256_hex(&payload_json))
}

fn canonical_payload_bytes<T: Serialize>(
    payload: &T,
    path: &Path,
) -> Result<Vec<u8>, SessionError> {
    let mut value = serde_json::to_value(payload).map_err(|e| SessionError::Json {
        path: path.to_path_buf(),
        source: e,
    })?;
    canonicalize_json(&mut value);
    serde_json::to_vec(&value).map_err(|e| SessionError::Json {
        path: path.to_path_buf(),
        source: e,
    })
}

fn canonicalize_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            // Rebuild object with sorted keys, recursively canonicalizing children.
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort();
            let mut new_map = serde_json::Map::with_capacity(map.len());
            for k in keys {
                if let Some(mut v) = map.remove(&k) {
                    canonicalize_json(&mut v);
                    new_map.insert(k, v);
                }
            }
            *map = new_map;
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                canonicalize_json(v);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Write the inventory artifact for a session.
pub fn persist_inventory(
    handle: &SessionHandle,
    session_id: &str,
    host_id: &str,
    artifact: InventoryArtifact,
) -> Result<PathBuf, SessionError> {
    let envelope = ArtifactEnvelope::new(session_id, host_id, artifact);
    persist_artifact(handle, INVENTORY_FILE, envelope)
}

/// Write the inference artifact for a session.
pub fn persist_inference(
    handle: &SessionHandle,
    session_id: &str,
    host_id: &str,
    artifact: InferenceArtifact,
) -> Result<PathBuf, SessionError> {
    let envelope = ArtifactEnvelope::new(session_id, host_id, artifact);
    persist_artifact(handle, INFERENCE_FILE, envelope)
}

/// Write the plan artifact for a session.
pub fn persist_plan(
    handle: &SessionHandle,
    session_id: &str,
    host_id: &str,
    artifact: PlanArtifact,
) -> Result<PathBuf, SessionError> {
    let envelope = ArtifactEnvelope::new(session_id, host_id, artifact);
    persist_artifact(handle, PLAN_FILE, envelope)
}

/// Write run metadata for a session.
pub fn persist_run_metadata(
    handle: &SessionHandle,
    session_id: &str,
    host_id: &str,
    metadata: RunMetadata,
) -> Result<PathBuf, SessionError> {
    let envelope = ArtifactEnvelope::new(session_id, host_id, metadata);
    persist_artifact(handle, META_FILE, envelope)
}

/// Load the inventory artifact with validation.
pub fn load_inventory(
    handle: &SessionHandle,
) -> Result<ArtifactEnvelope<InventoryArtifact>, SessionError> {
    load_artifact(handle, INVENTORY_FILE)
}

/// Load the inventory artifact but skip integrity validation.
pub fn load_inventory_unchecked(
    handle: &SessionHandle,
) -> Result<ArtifactEnvelope<InventoryArtifact>, SessionError> {
    load_artifact_unchecked(handle, INVENTORY_FILE)
}

/// Load the inference artifact with validation.
pub fn load_inference(
    handle: &SessionHandle,
) -> Result<ArtifactEnvelope<InferenceArtifact>, SessionError> {
    load_artifact(handle, INFERENCE_FILE)
}

/// Load the inference artifact but skip integrity validation.
pub fn load_inference_unchecked(
    handle: &SessionHandle,
) -> Result<ArtifactEnvelope<InferenceArtifact>, SessionError> {
    load_artifact_unchecked(handle, INFERENCE_FILE)
}

/// Load the plan artifact with validation.
pub fn load_plan(handle: &SessionHandle) -> Result<ArtifactEnvelope<PlanArtifact>, SessionError> {
    load_artifact(handle, PLAN_FILE)
}

/// Load run metadata with validation.
pub fn load_run_metadata(
    handle: &SessionHandle,
) -> Result<ArtifactEnvelope<RunMetadata>, SessionError> {
    load_artifact(handle, META_FILE)
}

/// Check which artifacts are present in a session directory.
pub fn list_artifacts(handle: &SessionHandle) -> Vec<String> {
    let mut present = Vec::new();
    for (name, rel) in [
        ("inventory", INVENTORY_FILE),
        ("inference", INFERENCE_FILE),
        ("plan", PLAN_FILE),
        ("run_metadata", META_FILE),
    ] {
        if handle.dir.join(rel).exists() {
            present.push(name.to_string());
        }
    }
    present
}

// ---------------------------------------------------------------------------
// SHA-256 (minimal, no external crate dependency)
// ---------------------------------------------------------------------------

/// Compute SHA-256 hex digest of bytes.
///
/// Uses a minimal implementation to avoid pulling in a heavy crypto crate
/// just for integrity hashing of small JSON payloads.
fn sha256_hex(data: &[u8]) -> String {
    let hash = sha256(data);
    let mut hex = String::with_capacity(SHA256_HEX_LEN);
    for byte in &hash {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

/// Minimal SHA-256 (FIPS 180-4). Not constant-time — fine for integrity, not crypto.
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Padding
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    // Process blocks
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut result = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        result[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_handle(tmp: &TempDir) -> SessionHandle {
        let dir = tmp.path().join("pt-20260201-120000-abcd");
        std::fs::create_dir_all(dir.join("scan")).unwrap();
        std::fs::create_dir_all(dir.join("inference")).unwrap();
        std::fs::create_dir_all(dir.join("decision")).unwrap();
        SessionHandle {
            id: pt_common::SessionId("pt-20260201-120000-abcd".to_string()),
            dir,
        }
    }

    fn sample_inventory() -> InventoryArtifact {
        InventoryArtifact {
            total_system_processes: 300,
            protected_filtered: 50,
            record_count: 2,
            records: vec![
                PersistedProcess {
                    pid: 1234,
                    ppid: 1,
                    uid: 1000,
                    start_id: "boot1:12345:1234".to_string(),
                    comm: "node".to_string(),
                    cmd: "node server.js".to_string(),
                    state: "S".to_string(),
                    start_time_unix: 1700000000,
                    elapsed_secs: 86400,
                    identity_quality: "Full".to_string(),
                },
                PersistedProcess {
                    pid: 5678,
                    ppid: 1234,
                    uid: 1000,
                    start_id: "boot1:12346:5678".to_string(),
                    comm: "worker".to_string(),
                    cmd: "node worker.js".to_string(),
                    state: "S".to_string(),
                    start_time_unix: 1700000100,
                    elapsed_secs: 86300,
                    identity_quality: "Full".to_string(),
                },
            ],
        }
    }

    fn sample_inference() -> InferenceArtifact {
        InferenceArtifact {
            candidate_count: 1,
            candidates: vec![PersistedInference {
                pid: 1234,
                start_id: "boot1:12345:1234".to_string(),
                classification: "abandoned".to_string(),
                posterior_useful: 0.05,
                posterior_useful_bad: 0.02,
                posterior_abandoned: 0.90,
                posterior_zombie: 0.03,
                confidence: "high".to_string(),
                recommended_action: "kill".to_string(),
                score: 92,
            }],
        }
    }

    fn sample_plan() -> PlanArtifact {
        PlanArtifact {
            action_count: 1,
            kill_count: 1,
            review_count: 0,
            spare_count: 0,
            actions: vec![PersistedPlanAction {
                pid: 1234,
                start_id: "boot1:12345:1234".to_string(),
                action: "kill".to_string(),
                expected_loss: 0.12,
                rationale: "P(abandoned)=0.90, low blast radius".to_string(),
            }],
        }
    }

    fn sample_metadata() -> RunMetadata {
        RunMetadata {
            pt_version: "2.1.0".to_string(),
            schema_version: SNAPSHOT_SCHEMA_VERSION.to_string(),
            host_id: "devbox1".to_string(),
            hostname: "devbox1.local".to_string(),
            os_family: "linux".to_string(),
            os_arch: "x86_64".to_string(),
            cores: 16,
            memory_total_gb: 64.0,
            priors_hash: "abc123".to_string(),
            policy_hash: "def456".to_string(),
            tags: BTreeMap::new(),
        }
    }

    #[test]
    fn test_sha256_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let digest = sha256_hex(b"");
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_abc() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let digest = sha256_hex(b"abc");
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_persist_load_inventory() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        let inv = sample_inventory();

        let path = persist_inventory(&handle, "test-session", "host1", inv.clone()).unwrap();
        assert!(path.exists());

        let loaded = load_inventory(&handle).unwrap();
        assert_eq!(loaded.payload.record_count, 2);
        assert_eq!(loaded.payload.records.len(), 2);
        assert_eq!(loaded.payload.records[0].pid, 1234);
        assert_eq!(loaded.session_id, "test-session");
    }

    #[test]
    fn test_persist_load_inference() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        let inf = sample_inference();

        persist_inference(&handle, "s1", "h1", inf).unwrap();
        let loaded = load_inference(&handle).unwrap();
        assert_eq!(loaded.payload.candidate_count, 1);
        assert!((loaded.payload.candidates[0].posterior_abandoned - 0.90).abs() < 0.01);
    }

    #[test]
    fn test_persist_load_plan() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        let plan = sample_plan();

        persist_plan(&handle, "s1", "h1", plan).unwrap();
        let loaded = load_plan(&handle).unwrap();
        assert_eq!(loaded.payload.kill_count, 1);
        assert_eq!(loaded.payload.actions[0].action, "kill");
    }

    #[test]
    fn test_persist_load_metadata() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        let meta = sample_metadata();

        persist_run_metadata(&handle, "s1", "h1", meta).unwrap();
        let loaded = load_run_metadata(&handle).unwrap();
        assert_eq!(loaded.payload.pt_version, "2.1.0");
        assert_eq!(loaded.payload.cores, 16);
    }

    #[test]
    fn test_integrity_check_detects_tampering() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        let inv = sample_inventory();

        persist_inventory(&handle, "s1", "h1", inv).unwrap();

        // Tamper with the file: change a PID in the stored JSON.
        let path = handle.dir.join(INVENTORY_FILE);
        let mut content = std::fs::read_to_string(&path).unwrap();
        content = content.replace("1234", "9999");
        std::fs::write(&path, &content).unwrap();

        let result = load_inventory(&handle);
        assert!(result.is_err(), "Should detect integrity mismatch");
    }

    #[test]
    fn test_redaction_none() {
        let cmd = "node --secret-token=abc123 server.js";
        assert_eq!(redact_cmd(cmd, RedactionPolicy::None), cmd);
    }

    #[test]
    fn test_redaction_full() {
        let cmd = "node server.js";
        assert_eq!(redact_cmd(cmd, RedactionPolicy::Full), REDACTED);
    }

    #[test]
    fn test_redaction_standard_sensitive() {
        assert_eq!(
            redact_cmd("app --password=foo", RedactionPolicy::Standard),
            REDACTED
        );
        assert_eq!(
            redact_cmd("export API_KEY=abc", RedactionPolicy::Standard),
            REDACTED
        );
        assert_eq!(
            redact_cmd("curl -H 'Bearer xyz'", RedactionPolicy::Standard),
            REDACTED
        );
    }

    #[test]
    fn test_redaction_standard_safe() {
        let cmd = "node server.js --port 3000";
        assert_eq!(redact_cmd(cmd, RedactionPolicy::Standard), cmd);
    }

    #[test]
    fn test_list_artifacts() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);

        assert!(list_artifacts(&handle).is_empty());

        persist_inventory(&handle, "s1", "h1", sample_inventory()).unwrap();
        let present = list_artifacts(&handle);
        assert_eq!(present, vec!["inventory"]);

        persist_plan(&handle, "s1", "h1", sample_plan()).unwrap();
        let present = list_artifacts(&handle);
        assert!(present.contains(&"inventory".to_string()));
        assert!(present.contains(&"plan".to_string()));
    }

    #[test]
    fn test_envelope_schema_version() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        persist_inventory(&handle, "s1", "h1", sample_inventory()).unwrap();
        let loaded = load_inventory(&handle).unwrap();
        assert_eq!(loaded.schema_version, SNAPSHOT_SCHEMA_VERSION);
    }

    #[test]
    fn test_envelope_host_and_session() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        persist_inference(&handle, "my-session", "my-host", sample_inference()).unwrap();
        let loaded = load_inference(&handle).unwrap();
        assert_eq!(loaded.session_id, "my-session");
        assert_eq!(loaded.host_id, "my-host");
    }
}
