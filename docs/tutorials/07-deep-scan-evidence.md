# Tutorial 07: Deep Scan Evidence

Goal: Collect richer per-process evidence when the quick evidence is ambiguous.

## 1) Raw deep records (Linux)

```bash
pt deep-scan --format json > /tmp/pt-deep.json
pt deep-scan --pids <pid> --format json
```

Deep scan reads more of `/proc` per process (I/O counters, scheduler statistics,
open file descriptors, sockets, cgroup) using time-bounded reads, so a process stuck
in the kernel cannot stall the scan. It prints records; it does not score them.

## 2) Use deep evidence in the plan

```bash
pt agent plan --deep --format json \
  | jq '.summary.deep_coverage, (.candidates[] | {pid, command_short, score, recommended_action})'
```

With `--deep`, the plan adds network, I/O and socket-queue evidence for the
candidates it deep-scanned; `summary.deep_coverage` says how many got each signal.

Notes:
- Deep scan costs more than a quick scan; use it when you need it.
- Without permission to read another user's `/proc` entries, those processes get
  quick evidence only (run as that user, or grant `cap_sys_ptrace`; see README).
- macOS has no deep scan.
