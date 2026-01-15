# Test Coverage Map (Mocked vs Real-System)

## Scope
This document inventories existing tests and classifies them as **real-system**, **fixture-based**, or **mocked**. It also highlights gaps for no-mock coverage.

### Classification
- **Real-system**: Executes against live OS resources (process table, /proc, sockets, systemd, etc.) without mocks/fakes.
- **Fixture-based**: Pure functions and parsers tested with static strings/files or generated data.
- **Mocked**: Behavior depends on fake outputs, mock binaries, or simulated environments.

---

## Inventory

### Rust unit tests (pt-core `src/*`)
**Status**: Predominantly fixture-based; a few real-system tests.

- **Fixture-based**
  - Parsers and pure logic across `collect`, `decision`, `inference`, `supervision`, `config`.
  - Examples: `collect/proc_parsers.rs`, `collect/network.rs`, `decision/expected_loss.rs`.
- **Real-system (limited)**
  - `action/signal.rs`: spawns `sleep` and uses real signals on Unix.
  - `collect/tool_runner.rs`: some tests invoke actual commands (real-system but shallow).
- **Ignored real-system tests**
  - `collect/deep_scan.rs`: integration tests against `/proc` are `#[ignore]`.
  - `collect/cpu_capacity.rs`, `collect/tick_delta.rs`, `collect/quick_scan.rs`: `#[ignore]` integration tests.

**Conclusion**: No complete, always-on real-system coverage for collectors or pipelines.

### Rust integration tests (`crates/pt-core/tests/*`)
- **Real-system (CLI-level)**
  - `e2e_workflow.rs`, `e2e_snapshot.rs`, `e2e_plan.rs`: invoke `pt-core` binary on live system. Limited to dry-run/JSON checks.
- **Fixture-based**
  - `schema_validation.rs`: validates schemas against fixture JSON.
  - `cli_help.rs`, `cli_formats.rs`, `cli_errors.rs`: CLI output + structure checks.
  - `exit_codes_comprehensive.rs`: pure exit-code semantics.
  - `session_persistence.rs`: fixture-driven persistence behavior.

### Rust tests (other crates)
- **pt-math** (`crates/pt-math/tests/properties.rs`): property-based math tests (fixture/random inputs).
- **pt-redact** (`crates/pt-redact/tests/redaction_integration.rs`): integration-style but string/fixture-driven.

### BATS tests (bash wrapper)
**Status**: Mostly real-system CLI checks, but shallow and not full workflow.

- `test/pt.bats`, `test/pt_robot.bats`, `test/pt_learning.bats`, `test/pt_config.bats`, `test/pt_errors.bats`, `test/version.bats`, `test/pt_errors.bats`:
  - Run `pt` and `pt robot` against the live system.
  - Skip based on gum/jq availability.
  - No full E2E pipeline, no action execution, minimal logging validation.
- **Mocking capability exists** (`test/test_helper/common.bash`) but is **not currently used** by tests.

---

## Coverage Gaps (No-Mock Track)

1. **/proc collector validation against live processes**
   - Parsers are tested with fixtures; no always-on tests using live `/proc` data.
2. **Network collector + inode correlation**
   - Parsing validated with fixtures; no real socket setup to validate mappings.
3. **cgroup/systemd detection in real environments**
   - Parsing relies on strings; no live systemd/cgroup tests (beyond ignored tests).
4. **ToolRunner timeouts/output truncation**
   - Unit tests exist but no deliberate, real-system validation of timeout/kill path.
5. **End-to-end CLI workflows with rich logging artifacts**
   - Existing BATS tests are shallow; no detailed structured logging or artifacts.

---

## Environment Constraints for No-Mock Tests
- **Linux-only** for `/proc`, cgroups, systemd, and network parser validation.
- **Systemd availability** must be probed and tests skipped when absent.
- **Permissions**: limited access to `/proc/[pid]` for other users may require running as same user.
- **Network**: ability to bind ephemeral sockets is required for network collector tests.

---

## Recommended Next Steps
See epic `process_triage-aii.6` for the no-mock test track and dependency graph.
