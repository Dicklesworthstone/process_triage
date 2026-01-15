# Redaction and Hashing Policy Specification

**Version**: 1.0.0
**Status**: Draft
**Bead**: process_triage-8n3

---

## 1. Overview

Process Triage handles data that may contain sensitive information:
- Command lines with API keys/tokens/passwords
- Environment variables with secrets
- File paths revealing usernames and project names
- Hostnames and IP addresses exposing infrastructure

This specification defines the **redaction policy** that governs what pt-core may persist, display, or export when process data contains sensitive information.

### 1.1 Goals

1. **User Trust**: Users can run pt without fear of secret exposure
2. **Shareability**: Bundles and reports can be safely shared
3. **Auditability**: Redaction decisions are traceable
4. **Pattern Matching**: Hashed values enable learning across sessions
5. **Compliance**: Support for privacy regulations (GDPR, etc.)

### 1.2 Threat Model

Assume attackers may obtain:
- Session artifacts on disk (~/.local/share/process_triage/)
- .ptb bundles sent to colleagues or support
- HTML reports emailed/posted
- Telemetry exported to fleet aggregation

**Non-cryptographic hashes (FNV, CRC, etc.) are NOT acceptable** for secrets due to trivial reversal via dictionary attacks.

---

## 2. Field Classes

Every string-like datum is classified into a **field class** with default handling.

### 2.1 Field Class Definitions

| Class | Description | Default Action | Risk Level |
|-------|-------------|----------------|------------|
| `cmdline` | Full command line | `normalize+hash` | Critical |
| `cmd` | Command name (argv[0]) | `allow` | Low |
| `cmdline_arg` | Individual argument | `detect+action` | Variable |
| `env_name` | Environment variable name | `allow` | Low |
| `env_value` | Environment variable value | `redact` | Critical |
| `path_home` | Path under $HOME | `normalize+hash` | High |
| `path_tmp` | Path under /tmp or temp | `normalize` | Medium |
| `path_system` | System path (/usr, /etc) | `allow` | Low |
| `path_project` | Project/work directory | `hash` | High |
| `hostname` | Machine hostname | `hash` | Medium |
| `ip_address` | IPv4/IPv6 address | `hash` | High |
| `url` | Full URL | `normalize+hash` | High |
| `url_host` | URL hostname | `hash` | Medium |
| `url_path` | URL path component | `normalize` | Medium |
| `url_credentials` | user:pass in URL | `redact` | Critical |
| `username` | System username | `hash` | High |
| `uid` | Numeric user ID | `allow` | Low |
| `pid` | Process ID | `allow` | None |
| `port` | Network port | `allow` | Low |
| `container_id` | Docker/container ID | `truncate` | Low |
| `systemd_unit` | Systemd unit name | `allow` | Low |
| `free_text` | Logs, messages | `detect+action` | Variable |

### 2.2 Risk Levels

| Risk Level | Description | Recommended Action |
|------------|-------------|-------------------|
| **Critical** | Secrets, credentials, tokens | `redact` always |
| **High** | PII, identifying info | `hash` or `normalize+hash` |
| **Medium** | Contextual info | `normalize` or `hash` |
| **Low** | Generally safe | `allow` |
| **None** | Never sensitive | `allow` |

---

## 3. Actions

### 3.1 Action Types

| Action | Description | Output Format |
|--------|-------------|---------------|
| `allow` | Persist as-is | Original value |
| `redact` | Remove/replace entirely | `[REDACTED]` |
| `hash` | Replace with keyed hash | `[HASH:abc123def]` |
| `normalize` | Pattern replacement (lossy) | Normalized value |
| `normalize+hash` | Normalize then hash | `[HASH:abc123def]` |
| `truncate` | Keep prefix/suffix only | `abc...xyz` |
| `detect+action` | Auto-detect and apply rule | Varies |

### 3.2 Action Semantics

#### 3.2.1 `allow`
No modification. Value persisted/displayed as-is.

```
Input:  /usr/bin/python3
Output: /usr/bin/python3
```

#### 3.2.2 `redact`
Complete removal. Original value is not recoverable.

```
Input:  API_KEY=sk-1234567890abcdef
Output: API_KEY=[REDACTED]
```

#### 3.2.3 `hash`
Keyed cryptographic hash. Enables pattern matching without revealing original.

```
Input:  /home/alice/myproject/src/main.rs
Output: [HASH:a7b2c9d1]
```

#### 3.2.4 `normalize`
Lossy pattern replacement. Removes variable parts while preserving structure.

```
Input:  /tmp/pytest-1234/test_foo/output.log
Output: /tmp/[TMP_SESSION]/test_foo/output.log
```

#### 3.2.5 `normalize+hash`
Normalize first, then hash the normalized form.

```
Input:  bun test --port 3000 /home/alice/project
Output: [HASH:e4f5g6h7]  (hash of "bun test --port=PORT [HOME]/[PROJECT]")
```

#### 3.2.6 `truncate`
Keep limited characters from start and/or end.

```
Input:  abc123def456ghi789jkl
Output: abc...jkl  (6-char truncation)
```

#### 3.2.7 `detect+action`
Auto-detect sensitivity using pattern matching, then apply appropriate action.

```
Input:  --token=ghp_abcdefghijklmnop
Detect: GitHub token pattern
Output: --token=[REDACTED]
```

---

## 4. Hashing Policy

### 4.1 Algorithm Requirements

| Requirement | Specification |
|-------------|---------------|
| **Algorithm** | HMAC-SHA256 |
| **Key Size** | 256 bits (32 bytes) |
| **Output Truncation** | 8 bytes (16 hex chars) default |
| **Output Format** | `[HASH:<salt_id>:<hex>]` |

### 4.2 Keyed Hashing

All hashes MUST be keyed to prevent rainbow table attacks:

```rust
fn redact_hash(value: &str, key: &[u8; 32], salt_id: &str) -> String {
    let canonical = canonicalize(value);
    let mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(canonical.as_bytes());
    let result = mac.finalize().into_bytes();
    let truncated = hex::encode(&result[..8]);  // 16 hex chars
    format!("[HASH:{}:{}]", salt_id, truncated)
}
```

### 4.3 Output Format

```
[HASH:<salt_id>:<hex_digest>]
```

| Component | Description | Example |
|-----------|-------------|---------|
| `salt_id` | Key identifier (rotatable) | `k1`, `k2`, `2026q1` |
| `hex_digest` | Truncated HMAC-SHA256 | `a7b2c9d1e4f5g6h7` |

**Examples**:
```
[HASH:k1:a7b2c9d1e4f5g6h7]
[HASH:2026q1:1234567890abcdef]
```

### 4.4 Key Management

#### Key Storage

```
~/.config/process_triage/redaction_key
```

| Property | Specification |
|----------|---------------|
| **Format** | 32 raw bytes |
| **Permissions** | `0600` (owner read/write only) |
| **Generation** | `getrandom()` or `/dev/urandom` |

#### Key File Structure

```json
{
  "schema_version": "1.0.0",
  "keys": {
    "k1": {
      "created_at": "2026-01-01T00:00:00Z",
      "algorithm": "hmac-sha256",
      "key_material": "<base64-encoded-32-bytes>",
      "status": "active"
    }
  },
  "active_key_id": "k1"
}
```

#### Key Rotation

1. Generate new key with new `salt_id`
2. Mark old key as `deprecated`
3. New sessions use new key
4. Old hashes remain valid (salt_id identifies key)

**Key material MUST NEVER be written to**:
- Telemetry files
- Bundles
- Reports
- Logs

### 4.5 Hash Stability

Hashes are stable within:
- Same key/salt_id
- Same canonicalization version

Hashes change when:
- Key is rotated
- Canonicalization rules change

---

## 5. Canonicalization

### 5.1 Purpose

Canonicalization normalizes inputs before hashing to enable pattern matching while removing variable parts.

### 5.2 Canonicalization Rules

| Rule | Input | Output |
|------|-------|--------|
| **Trim whitespace** | `"  foo bar  "` | `"foo bar"` |
| **Collapse spaces** | `"foo    bar"` | `"foo bar"` |
| **Lowercase** | `"FOO"` | `"foo"` |
| **Home directory** | `/home/alice/...` | `[HOME]/...` |
| **Temp directory** | `/tmp/foo123/...` | `[TMP]/...` |
| **PID placeholder** | `--pid 12345` | `--pid [PID]` |
| **Port placeholder** | `--port 3000` | `--port [PORT]` |
| **Numeric suffix** | `test_1234` | `test_[N]` |
| **UUID placeholder** | `a1b2c3d4-e5f6-...` | `[UUID]` |
| **Timestamp** | `2026-01-15T14:30:22` | `[TIMESTAMP]` |
| **URL credentials** | `user:pass@host` | `[CRED]@host` |

### 5.3 Canonicalization Version

Canonicalization rules are versioned because changes affect hash outputs:

```json
{
  "canonicalization_version": "1.0.0",
  "rules_applied": ["trim", "collapse_spaces", "home_dir", "temp_dir", "pid", "port"]
}
```

### 5.4 Canonicalization Examples

#### Command Line

```
Input:  /home/alice/project/bin/test --port 3000 --pid 12345 /tmp/test_abc123
Canon:  [HOME]/project/bin/test --port [PORT] --pid [PID] [TMP]/test_[N]
```

#### URL

```
Input:  https://alice:secret123@api.example.com:8443/v1/data?token=abc
Canon:  https://[CRED]@api.example.com:[PORT]/v1/data?token=[REDACTED]
```

#### Path

```
Input:  /home/alice/.config/myapp/settings.json
Canon:  [HOME]/.config/myapp/settings.json
```

---

## 6. Secret Detection

### 6.1 Detection Patterns

Auto-detect secrets using regex patterns:

| Pattern Type | Regex | Action |
|--------------|-------|--------|
| **AWS Access Key** | `AKIA[0-9A-Z]{16}` | `redact` |
| **AWS Secret Key** | `[A-Za-z0-9/+=]{40}` (context: AWS) | `redact` |
| **GitHub Token** | `gh[pousr]_[A-Za-z0-9_]{36,}` | `redact` |
| **GitLab Token** | `glpat-[A-Za-z0-9-_]{20,}` | `redact` |
| **Slack Token** | `xox[baprs]-[A-Za-z0-9-]+` | `redact` |
| **JWT** | `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` | `redact` |
| **Private Key** | `-----BEGIN.*PRIVATE KEY-----` | `redact` |
| **Password Arg** | `--password[= ][^ ]+` | `redact` |
| **Token Arg** | `--token[= ][^ ]+` | `redact` |
| **API Key Arg** | `--api[-_]?key[= ][^ ]+` | `redact` |
| **Secret Env** | `.*_(KEY\|TOKEN\|SECRET\|PASSWORD\|CREDENTIAL)=.*` | `redact` |
| **Connection String** | `(postgres\|mysql\|mongodb)://[^@]+@` | `normalize` |

### 6.2 Context-Aware Detection

Some patterns need context:

```rust
fn detect_secret(value: &str, context: &Context) -> Option<SecretType> {
    // High-entropy string in env var value
    if context.field_class == "env_value" && is_high_entropy(value) {
        return Some(SecretType::PossibleSecret);
    }

    // Argument after --token, --password, etc.
    if context.previous_token.is_some_sensitive_flag() {
        return Some(SecretType::SensitiveArg);
    }

    None
}
```

### 6.3 Entropy Analysis

For ambiguous cases, use Shannon entropy:

```rust
fn is_high_entropy(value: &str) -> bool {
    let entropy = shannon_entropy(value);
    // Base64-encoded secrets typically have entropy > 4.5
    entropy > 4.5 && value.len() >= 16
}
```

---

## 7. Export Profiles

### 7.1 Profile Definitions

| Profile | Description | Use Case |
|---------|-------------|----------|
| `minimal` | Aggregate stats only | Public sharing |
| `safe` | Evidence + features, strings redacted/hashed | Team sharing |
| `forensic` | Raw evidence with explicit allowlist | Support tickets |

### 7.2 Profile Specifications

#### 7.2.1 `minimal` Profile

| Data Type | Included | Format |
|-----------|----------|--------|
| Summary stats | Yes | Aggregate counts |
| Session metadata | Yes | Non-identifying |
| Candidate list | No | - |
| Evidence ledger | No | - |
| Command lines | No | - |
| Paths | No | - |
| Raw outputs | No | - |

#### 7.2.2 `safe` Profile

| Data Type | Included | Format |
|-----------|----------|--------|
| Summary stats | Yes | Aggregate counts |
| Session metadata | Yes | hostname/user hashed |
| Candidate list | Yes | PIDs, scores, recommendations |
| Evidence ledger | Yes | With hashed strings |
| Command lines | Yes | Normalized + hashed |
| Paths | Yes | Normalized (home → [HOME]) |
| Raw outputs | No | - |
| Environment vars | No | - |

#### 7.2.3 `forensic` Profile

| Data Type | Included | Format |
|-----------|----------|--------|
| Summary stats | Yes | Aggregate counts |
| Session metadata | Yes | Optional plaintext |
| Candidate list | Yes | Full details |
| Evidence ledger | Yes | Full details |
| Command lines | Yes | Explicit allowlist only |
| Paths | Yes | Explicit allowlist only |
| Raw outputs | Optional | If allowlisted |
| Environment vars | No | Never (too risky) |

**Forensic requires explicit allowlist**:
```json
{
  "profile": "forensic",
  "allow_raw": {
    "cmdline_patterns": ["^/usr/bin/", "^python3? "],
    "path_patterns": ["^/var/log/"],
    "max_cmd_length": 500
  }
}
```

### 7.3 Profile Recording

Every artifact records its profile:

```json
{
  "redaction": {
    "policy_version": "1.0.0",
    "canonicalization_version": "1.0.0",
    "profile": "safe",
    "key_id": "k1",
    "applied_at": "2026-01-15T14:30:00Z"
  }
}
```

---

## 8. Policy Configuration

### 8.1 Policy File

```
~/.config/process_triage/redaction_policy.json
```

### 8.2 Policy Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["schema_version", "default_profile", "field_rules"],
  "properties": {
    "schema_version": {
      "type": "string",
      "const": "1.0.0"
    },
    "default_profile": {
      "type": "string",
      "enum": ["minimal", "safe", "forensic"]
    },
    "field_rules": {
      "type": "object",
      "additionalProperties": {
        "$ref": "#/$defs/field_rule"
      }
    },
    "detection_patterns": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/detection_pattern"
      }
    },
    "custom_rules": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/custom_rule"
      }
    }
  }
}
```

### 8.3 Default Policy

```json
{
  "schema_version": "1.0.0",
  "default_profile": "safe",
  "hash_truncation_bytes": 8,
  "field_rules": {
    "cmdline": {"action": "normalize+hash"},
    "cmd": {"action": "allow"},
    "env_value": {"action": "redact"},
    "path_home": {"action": "normalize+hash"},
    "path_tmp": {"action": "normalize"},
    "path_system": {"action": "allow"},
    "hostname": {"action": "hash"},
    "ip_address": {"action": "hash"},
    "url": {"action": "normalize+hash"},
    "url_credentials": {"action": "redact"},
    "username": {"action": "hash"},
    "uid": {"action": "allow"},
    "pid": {"action": "allow"}
  },
  "detection_enabled": true,
  "entropy_threshold": 4.5
}
```

---

## 9. Implementation Contract

### 9.1 Redaction Engine Interface

```rust
pub trait RedactionEngine {
    /// Apply redaction policy to a value
    fn redact(&self, value: &str, field_class: FieldClass) -> RedactedValue;

    /// Apply redaction to structured data
    fn redact_record(&self, record: &mut Record);

    /// Get current policy version
    fn policy_version(&self) -> &str;

    /// Get current key ID (not the key itself)
    fn key_id(&self) -> &str;
}

pub struct RedactedValue {
    pub output: String,
    pub action_applied: Action,
    pub original_hash: Option<String>,  // For forensic reference
}
```

### 9.2 Redaction Points

Redaction MUST be applied at:

| Point | Description |
|-------|-------------|
| **Collection** | When reading /proc, ps output |
| **Storage** | Before writing to telemetry |
| **Display** | Before TUI/CLI output |
| **Export** | When creating bundles/reports |
| **Logging** | Before any log output |

### 9.3 Audit Trail

All redaction decisions are logged:

```json
{
  "ts": "2026-01-15T14:30:00Z",
  "field_class": "cmdline",
  "action": "normalize+hash",
  "input_hash": "[HASH:k1:original]",
  "output": "[HASH:k1:a7b2c9d1]"
}
```

---

## 10. Compliance

### 10.1 GDPR Considerations

| GDPR Requirement | Implementation |
|------------------|----------------|
| **Right to erasure** | Key rotation + session deletion |
| **Data minimization** | Minimal profile by default for exports |
| **Purpose limitation** | Telemetry used only for pt functionality |
| **Security** | Keyed hashing, encrypted storage optional |

### 10.2 SOC 2 Considerations

| Control | Implementation |
|---------|----------------|
| **CC6.1 Logical access** | Key file permissions (0600) |
| **CC6.7 Transmission** | Hashed values in bundles |
| **CC7.2 Monitoring** | Audit log of redaction actions |

---

## 11. Testing Requirements

### 11.1 Canary Tests

A fixed set of "canary strings" MUST never appear in persisted outputs:

```rust
const CANARY_SECRETS: &[&str] = &[
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "password123!@#",
    "super_secret_token",
];

#[test]
fn test_no_canary_leakage() {
    for canary in CANARY_SECRETS {
        let output = redact(canary, FieldClass::CmdlineArg);
        assert!(!output.contains(canary));
    }
}
```

### 11.2 Hash Stability Tests

```rust
#[test]
fn test_hash_stability() {
    let key = load_test_key();
    let input = "/home/alice/project";

    let hash1 = redact_hash(input, &key, "test");
    let hash2 = redact_hash(input, &key, "test");

    assert_eq!(hash1, hash2);  // Same key = same hash
}

#[test]
fn test_hash_changes_with_key() {
    let key1 = generate_key();
    let key2 = generate_key();
    let input = "/home/alice/project";

    let hash1 = redact_hash(input, &key1, "k1");
    let hash2 = redact_hash(input, &key2, "k2");

    assert_ne!(hash1, hash2);  // Different keys = different hashes
}
```

### 11.3 Log Leak Tests

```rust
#[test]
fn test_logs_never_leak_secrets() {
    let engine = RedactionEngine::new(test_policy());

    // Trigger an error with secret in context
    let result = engine.process_with_error("--token=secret123");

    // Check error message doesn't contain secret
    let error_msg = result.unwrap_err().to_string();
    assert!(!error_msg.contains("secret123"));
}
```

---

## 12. References

- PLAN: §8.1 Telemetry Lake
- OWASP Secrets Management: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- HMAC-SHA256: RFC 2104
- Bead: process_triage-k4yc.1 (Implementation)
- Bead: process_triage-4r8 (Telemetry Schema)
