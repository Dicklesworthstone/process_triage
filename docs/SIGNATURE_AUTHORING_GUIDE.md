# Signature Authoring Guide

This guide explains how to create safe, precise process signatures for Process Triage (pt). A signature is a structured pattern that identifies a specific process class and optionally supplies conservative priors and expectations. Signatures influence recommendations but never bypass safety gates.

## 1) What a signature is (and is not)

A signature:
- Matches processes using structured patterns (name, args, env, cwd, sockets, parent, PID files).
- Can adjust priors (Bayesian probability of useful/abandoned/zombie/useful_bad).
- Can set behavioral expectations (typical lifetime, CPU profile, IO expectations).

A signature is not:
- A direct kill rule. All actions still require safety gates, identity checks, and confirmation.
- A replacement for protected patterns or policy enforcement.

## 2) Where signatures live

Sources:
- Built-in signatures are defined in `crates/pt-core/src/supervision/signature.rs`.
- User signatures live at `~/.config/process_triage/signatures.json`.
- Additional signature files can be loaded via `pt ... --signatures <path>` (JSON or TOML).

Schema version:
- Current `schema_version` is 2 (see `SignatureSchema` in `crates/pt-core/src/supervision/signature.rs`).

## 3) Signature schema (v2)

A signature file wraps one or more signatures:

```json
{
  "schema_version": 2,
  "metadata": {
    "description": "Custom signatures for my dev machine",
    "author": "you",
    "url": ""
  },
  "signatures": [
    {
      "name": "jest-worker",
      "category": "agent",
      "confidence_weight": 0.85,
      "notes": "Jest test worker",
      "priority": 120,
      "patterns": {
        "process_names": ["^node$"],
        "arg_patterns": ["jest", "--runInBand"],
        "environment_vars": {"JEST_WORKER_ID": ".*"},
        "working_dir_patterns": ["/repo/.+"],
        "socket_paths": ["/tmp/jest-"],
        "pid_files": [],
        "parent_patterns": ["^bash$", "^zsh$"],
        "min_matches": 2
      },
      "priors": {
        "abandoned": {"alpha": 2.0, "beta": 6.0},
        "useful": {"alpha": 6.0, "beta": 2.0}
      },
      "expectations": {
        "typical_lifetime_seconds": 600,
        "max_normal_lifetime_seconds": 3600,
        "cpu_during_run": 0.7,
        "idle_cpu_normal": false,
        "expected_memory_bytes": 536870912,
        "expects_network": false,
        "expects_disk_io": true
      }
    }
  ]
}
```

## 4) Pattern DSL (matching rules)

All patterns are evaluated using Rust regex semantics. The following fields are available under `patterns`:

- `process_names`: regex patterns applied to the process name (`comm`). Use anchors (`^...$`) for exact matches.
- `arg_patterns`: regex patterns applied to the full command line. All arg patterns must match (AND).
- `environment_vars`: map of ENV_VAR -> regex. If the regex is empty or `.*`, presence is enough.
- `working_dir_patterns`: regex applied to the process working directory.
- `socket_paths`: path prefix matches against open socket paths.
- `pid_files`: exact PID file paths (if supported by the detector).
- `parent_patterns`: regex applied to parent process name (`comm`).
- `min_matches`: minimum number of pattern types that must match (default 1).

Conflict resolution:
- Matches are scored by match level and then weighted by `confidence_weight`.
- If scores tie, higher `priority` wins.
- Use higher `priority` for more specific signatures to beat generic ones.

## 5) Safety constraints

Do not write signatures that match protected processes or broad system patterns.

Bad patterns (too broad):
- `process_names = [".*"]`
- `process_names = ["^.*$"]`
- `arg_patterns = ["-"]` (matches almost anything)

Good patterns (specific):
- `process_names = ["^node$"], arg_patterns = ["jest", "--runInBand"], min_matches = 2`
- `environment_vars = {"VSCODE_PID": ".*"}, parent_patterns = ["^code$"]`

Rules of thumb:
- Anchor `process_names` with `^` and `$`.
- Prefer `min_matches >= 2` for high-risk actions (reduces false positives).
- Avoid matching by env var only unless it is uniquely identifying.
- Never target system services (systemd, sshd, dbus, docker, etc.).
- Keep `confidence_weight` conservative (0.6 to 0.9) unless the match is exact.

## 6) Priors and calibration

Signatures can override class priors via Beta distributions:

- `abandoned`, `useful`, `useful_bad`, `zombie` each accept `{alpha, beta}`.
- Alpha/beta must be > 0.
- Mean = alpha / (alpha + beta).

Guidance:
- Use small, conservative values (e.g., Beta(2,2), Beta(3,5)).
- Avoid extreme priors (e.g., Beta(50,1)) unless you have strong evidence.
- If you set `abandoned` high, set `useful` low explicitly, and vice versa.

## 7) Expectations (behavioral hints)

`expectations` describe normal behavior to help detect anomalies:

- `typical_lifetime_seconds`: typical runtime for normal operation.
- `max_normal_lifetime_seconds`: beyond this, process becomes suspicious.
- `cpu_during_run`: expected CPU fraction (0.0 to 1.0).
- `idle_cpu_normal`: true if idle CPU is expected.
- `expected_memory_bytes`: rough memory footprint.
- `expects_network` / `expects_disk_io`: expected IO traits.

Validation rules:
- `cpu_during_run` must be within 0.0 to 1.0.
- `typical_lifetime_seconds` must not exceed `max_normal_lifetime_seconds`.

## 8) Testing workflow

1) Validate your signature file:

```bash
pt signature validate
```

2) Test match behavior:

```bash
pt signature test node --cmdline "node ./node_modules/.bin/jest --runInBand" --all
```

3) Run a scan with your signatures:

```bash
pt scan --signatures /path/to/signatures.json
```

4) Check that candidates show `matched_signature` in JSON output:

```bash
pt robot plan --format json --signatures /path/to/signatures.json | jq '.candidates[] | {pid, cmd_short, matched_signature}'
```

If your signature matches unexpectedly, tighten patterns or increase `min_matches`.

## 9) Sharing and versioning

- Export built-in and user signatures:

```bash
pt signature export /tmp/signatures.json
```

- Keep `schema_version` intact when sharing.
- Avoid embedding sensitive paths or secrets in regexes.
- If distributing signatures, include a short changelog and intended scope.

## 10) Contribution workflow (project repo)

To contribute built-in signatures:
- Edit `crates/pt-core/src/supervision/signature.rs` and add a new `SupervisorSignature` in `add_default_signatures()`.
- Add tests in `crates/pt-core/src/supervision/signature.rs` or `crates/pt-core/src/supervision/supervision_tests.rs`.
- Run `cargo test -p pt-core signature` (or `cargo test -p pt-core supervision::signature`).

## 11) Signature lint checklist

Use this checklist before sharing:
- Name is unique, lowercase, and descriptive.
- Category is correct (agent, ide, ci, orchestrator, terminal, other).
- `process_names` patterns are anchored and specific.
- `arg_patterns` are not overly broad; AND semantics are intentional.
- `min_matches` is >= 2 for risky signatures.
- `confidence_weight` is conservative.
- Priors are weakly informative; no extreme alpha/beta.
- Expectations are consistent and validated.
- Signature passes `pt signature validate` and `pt signature test`.
- No protected/system process matches are possible.

