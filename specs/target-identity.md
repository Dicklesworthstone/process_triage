# Target Identity and Privilege Contracts

**Version**: 1.0.0
**Status**: Draft
**Bead**: process_triage-o8m

---

## 1. Overview

Any action that changes process state (terminate, pause, resume) must target the **correct process instance** and respect **privilege boundaries**. PID reuse makes targeting unsafe unless we verify a stable identity tuple immediately before action. This spec defines:

- The identity tuple (fields and how computed)
- The `start_id` format (stable across PID reuse)
- Revalidation protocol and error handling
- Privilege levels and cross-UID policy
- Locking semantics to prevent concurrent actions

---

## 2. Identity Tuple

### 2.1 Required Fields

Each action target MUST carry the following identity fields (captured at scan or plan time):

| Field | Type | Source | Notes |
|---|---|---|---|
| `pid` | int | `ps`/`/proc/<pid>` | Process ID at scan time |
| `start_time_ticks` | int | `/proc/<pid>/stat` field 22 | Jiffies since boot |
| `boot_id` | string | `/proc/sys/kernel/random/boot_id` | Uniquely identifies boot epoch |
| `uid` | int | `/proc/<pid>/status` | Real UID |
| `euid` | int | `/proc/<pid>/status` | Effective UID |
| `start_id` | string | derived | Stable identity key |

### 2.2 Optional Fields (Recommended)

These strengthen revalidation and forensics without exposing raw command lines:

| Field | Type | Source | Notes |
|---|---|---|---|
| `exe_inode` | int | `/proc/<pid>/exe` stat | Used to detect PID reuse with different binary |
| `exe_dev` | int | `/proc/<pid>/exe` stat | Device id for inode pair |
| `cmdline_sha256` | string | `/proc/<pid>/cmdline` | Hash only, no raw cmdline |
| `start_time_unix_ms` | int | derived | Convenience for logs and UI |

### 2.3 start_id Format

`start_id` MUST uniquely identify a process instance across PID reuse. It is defined as:

```
start_id = "<boot_id>:<start_time_ticks>:<pid>"
```

Example:

```
boot_id = 9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f
start_time_ticks = 123456789
pid = 42137
start_id = 9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:123456789:42137
```

This combination is stable within a boot epoch and robust against PID reuse.

### 2.4 start_time_unix_ms Derivation

Compute boot time and convert ticks to epoch time:

```
boot_time_unix_s = read /proc/stat (btime)
start_time_unix_ms = (boot_time_unix_s * 1000) + (start_time_ticks * 1000 / HZ)
```

Use `sysconf(_SC_CLK_TCK)` for `HZ` when available.

---

## 3. Revalidation Protocol

Revalidation MUST occur immediately before any destructive action.

### 3.1 Required Checks

1. Read `/proc/<pid>/stat` and confirm `start_time_ticks` matches.
2. Read `/proc/<pid>/status` and confirm `uid` and `euid` match.
3. Read `/proc/sys/kernel/random/boot_id` and confirm `boot_id` matches.
4. If present, verify `exe_inode` + `exe_dev` and/or `cmdline_sha256`.

If any check fails, **abort the action** with `reason=identity_mismatch` and include the observed values. The plan/apply result MUST set:

- `status`: `skipped`
- `reason`: `identity_mismatch`
- `requires_rescan`: `true`

Include an `identity_observed` object in the result payload with any values that mismatched (e.g., `start_time_ticks`, `uid`, `euid`, `boot_id`, `exe_inode`, `exe_dev`, `cmdline_sha256`) to aid debugging and audit trails.

### 3.2 Timing and TOCTOU

- Revalidation happens **after** lock acquisition and **immediately before** action execution.
- If revalidation fails, **do not attempt any signal**.
- If the process disappears, return `reason=not_running` (not an error).

---

## 4. Privilege Model

### 4.1 Privilege Levels

| Level | Description | Allowed Targets |
|---|---|---|
| `own_user` | Default, no elevation | Only processes owned by invoking user |
| `sudo` | Use sudo (non-interactive) | Cross-UID if policy allows |
| `root` | Running as root | Any process (subject to policy) |

### 4.2 Rules

- Default level is `own_user`.
- Cross-UID targeting is **disabled by default**.
- `sudo` mode MUST use non-interactive `sudo -n` in robot mode. If password is required, return `reason=sudo_required`.
- Even with elevation, **protected processes** (system services) remain blocked by policy.
- Always record `invoker_uid`, `privilege_level`, and whether elevation was used in action logs.

### 4.3 Policy Gates

Policy must explicitly allow cross-UID actions (e.g., `policy.privilege.allow_cross_uid=true`). Otherwise, candidates with `uid != invoker_uid` are marked:

- `recommended_action`: `skip`
- `reason`: `privilege_blocked`

---

## 5. Locking and Coordination

### 5.1 Lock Scope and Location

Locks prevent concurrent destructive actions from multiple pt instances.

- Scope: per user, per host
- Location: `${XDG_DATA_HOME:-$HOME/.local/share}/process_triage/locks/`
- Filename: `pt-<uid>.lock`

### 5.2 Lock File Contents

Lock file is JSON (for debugging) and includes:

```
{
  "schema_version": "1.0.0",
  "lock_id": "lock-20260115-145300-a7xq",
  "holder_pid": 12345,
  "holder_session_id": "pt-20260115-145200-x9qv",
  "started_at": "2026-01-15T14:53:00Z",
  "expires_at": "2026-01-15T15:03:00Z",
  "mode": "robot_apply",
  "user": "alice",
  "host": "devbox-1",
  "command": "pt agent apply --recommended --yes"
}
```

### 5.3 Acquisition and Staleness

- Lock acquisition MUST use `flock` (or equivalent) on the lock file.
- Default TTL: 10 minutes. Extendable by the holder while active.
- A lock is stale if `holder_pid` is not alive OR `now > expires_at`.
- Stale locks may be cleared automatically after revalidation of staleness.

### 5.4 Contention Behavior

- Interactive mode may offer `--wait` to block until the lock releases.
- Robot mode MUST be non-blocking by default and return:
  - `status`: `blocked`
  - `reason`: `lock_busy`
  - `lock_holder`: summary from lock file

### 5.5 Lock Ordering

- Acquire lock **before** identity revalidation.
- Hold lock through action execution and result recording.
- Release lock on completion or failure (including identity mismatch).

---

## 6. Error Codes and Reasons

Standardized reasons for action failures:

| Reason | Meaning |
|---|---|
| `identity_mismatch` | PID reuse or process changed |
| `not_running` | Process exited before action |
| `privilege_blocked` | Cross-UID not permitted |
| `sudo_required` | sudo needs password / no privilege |
| `lock_busy` | Another pt instance holds lock |

---

## 7. JSON Schema

See `specs/schemas/target-identity.schema.json` for the identity object.

---

## 8. Example Identity Object

```json
{
  "schema_version": "1.0.0",
  "pid": 42137,
  "start_time_ticks": 123456789,
  "boot_id": "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f",
  "uid": 1000,
  "euid": 1000,
  "start_id": "9d2d4e20-8c2b-4a3a-a8a2-90bcb7a1d86f:123456789:42137",
  "cmdline_sha256": "ab12cd34ef56ab78cd90ef12ab34cd56ef78ab90cd12ef34ab56cd78ef90ab12",
  "start_time_unix_ms": 1768485187123
}
```
