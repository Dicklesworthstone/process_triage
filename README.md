# pt

<div align="center">

**Process Triage** — Interactive zombie/abandoned process killer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

`pt` is a CLI tool that identifies and kills abandoned processes on your system. It uses heuristics to score processes by how likely they are to be zombies, remembers your past decisions to improve future suggestions, and presents an interactive UI for reviewing and killing candidates.

<div align="center">
<h3>Quick Install</h3>

```bash
# Clone and add to PATH
git clone https://github.com/Dicklesworthstone/process_triage.git
ln -s $(pwd)/process_triage/bin/pt ~/.local/bin/pt

# Or just run directly
./bin/pt
```

<p><em>Works on Linux. Requires gum (auto-installs if missing).</em></p>
</div>

---

## TL;DR

**The Problem**: Long-running development machines accumulate zombie processes — stuck tests, abandoned dev servers, orphaned agent shells. These consume CPU and memory, and manually hunting them is tedious.

**The Solution**: `pt` automatically identifies likely zombies, pre-selects the most suspicious ones for killing, and learns from your decisions to improve future suggestions.

### Why Use pt?

| Feature | What It Does |
|---------|--------------|
| **Smart Scoring** | Heuristics identify stuck tests, old dev servers, orphaned processes |
| **Learning Memory** | Remembers your kill/spare decisions for similar processes |
| **Pre-selection** | Most suspicious processes are pre-selected for quick review |
| **Interactive UI** | Beautiful gum-based interface with multi-select |
| **Safe by Default** | Confirms before killing, tries SIGTERM before SIGKILL |
| **System Aware** | Never flags system services (systemd, sshd, docker, etc.) |

### Quick Example

```bash
# Interactive mode (default) - scan, review, kill
pt

# Just scan without killing
pt scan

# View past decisions
pt history

# Clear learned decisions
pt clear
```

---

## How It Works

### Process Scoring

Each process receives a score based on multiple factors:

| Factor | Score Impact | Rationale |
|--------|-------------|-----------|
| Age > 1 week | +50 | Very old processes are rarely intentional |
| Age > 2 days | +30 | Old processes need review |
| Age > 1 day | +20 | Mildly suspicious |
| PPID = 1 (orphaned) | +25 | Parent died, likely abandoned |
| Stuck test (age > 1h) | +40 | Tests should complete quickly |
| Old dev server (> 2d) | +20 | Dev servers get forgotten |
| Old agent shell (> 1d) | +35 | Claude/Codex shells get abandoned |
| High memory + old | +15 | Resource hogs deserve attention |
| System service | -100 | Never kill these |
| Killed similar before | +20 | Learn from history |
| Spared similar before | -30 | Respect past decisions |

### Recommendations

Based on score:

- **KILL** (score >= 50): Pre-selected for killing
- **REVIEW** (score 20-49): Worth checking
- **SPARE** (score < 20): Probably safe

### Decision Memory

When you kill or spare a process, `pt` remembers the pattern. For example, if you spare `gunicorn --workers 4`, similar gunicorn processes will be scored lower in the future.

Patterns are normalized (PIDs removed, ports generalized) so decisions apply across sessions.

---

## Commands

### `pt` or `pt run`

Interactive mode. Scans processes, presents candidates sorted by score, lets you select which to kill.

```bash
pt
pt run
```

### `pt scan`

Scan-only mode. Shows candidates without killing. Useful for reviewing system state.

```bash
pt scan
```

### `pt history`

Show past kill/spare decisions.

```bash
pt history
```

### `pt clear`

Clear all learned decisions (start fresh).

```bash
pt clear
```

### `pt help`

Show help message.

```bash
pt help
pt --help
pt -h
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROCESS_TRIAGE_CONFIG` | `~/.config/process_triage` | Config directory |
| `XDG_CONFIG_HOME` | `~/.config` | XDG base (used if PROCESS_TRIAGE_CONFIG not set) |

### Files

| File | Purpose |
|------|---------|
| `~/.config/process_triage/decisions.json` | Learned kill/spare decisions |
| `~/.config/process_triage/protected.txt` | Custom protected patterns (future) |
| `~/.config/process_triage/triage.log` | Operation log |

---

## Process Detection Patterns

### Detected as Suspicious

- **Test runners**: `bun test`, `jest`, `pytest`, `cargo test`, `npm test`, `vitest` (if running > 1 hour)
- **Dev servers**: Processes with `--hot`, `--watch`, `next dev`, `vite` (if running > 2 days)
- **Agent shells**: Processes matching `claude`, `codex`, `gemini`, `anthropic` + `bash`/`sh` (if running > 1 day)
- **Orphaned processes**: Any process with PPID = 1
- **Old processes**: Anything running > 24 hours gets some suspicion

### Protected (Never Flagged)

- `systemd`, `dbus`, `pulseaudio`, `pipewire`
- `sshd`, `cron`, `docker`

---

## Dependencies

- **gum**: Charm's CLI component toolkit (auto-installs if missing)
- **jq**: JSON processor (optional, for decision memory)
- **bash**: Version 4.0+ (for arrays and mapfile)
- **standard utils**: `ps`, `kill`, `grep`, `awk`, `cut`, `sort`

### Gum Installation

`pt` automatically installs gum if not found, supporting:

- apt (Debian/Ubuntu)
- dnf (Fedora/RHEL)
- pacman (Arch)
- brew (macOS/Linuxbrew)
- nix-env (NixOS)
- Direct binary download (fallback)

---

## Safety

### What pt Does

1. Uses SIGTERM first (graceful shutdown)
2. Only uses SIGKILL if SIGTERM fails
3. Requires confirmation before killing
4. Logs all operations
5. Saves decisions for future learning

### What pt Never Does

1. Kill system services (systemd, sshd, etc.)
2. Kill without confirmation
3. Modify any files outside its config directory
4. Access the network

---

## Example Session

```
╔═══════════════════════════════════════════════╗
║                                               ║
║  Process Triage                               ║
║  Interactive zombie/abandoned process killer  ║
║                                               ║
╚═══════════════════════════════════════════════╝

  Load: 5.17 4.89 10.23 (64 cores) | Memory: 281Gi / 499Gi

Found 7 candidate(s) for review:

[KILL]=recommended  [REVIEW]=check  [SPARE]=probably safe

[KILL]  PID:12345 11d    2048MB (75) │ bun test --watch...
[KILL]  PID:23456 3d     512MB  (55) │ /bin/bash -c claude...
[REVIEW] PID:34567 26h   128MB  (25) │ next dev --port 3000...
[SPARE] PID:45678 2h     64MB   (10) │ gunicorn --workers 4...

> Select processes to KILL (space to toggle, enter to confirm)
```

---

## Troubleshooting

### "gum: command not found" after install

The auto-installer may need sudo. Run manually:

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install gum

# Or download binary
curl -fsSL https://github.com/charmbracelet/gum/releases/download/v0.14.1/gum_0.14.1_linux_amd64.tar.gz | tar xz
sudo mv gum /usr/local/bin/
```

### No candidates found

If `pt scan` shows no candidates:

1. Check minimum age — by default, only processes > 1 hour are considered
2. Your system may be clean — congratulations!

### Decision memory not working

Ensure `jq` is installed:

```bash
sudo apt install jq  # or equivalent
```

---

## Origins & Authors

Created by **Jeffrey Emanuel** to tame the chaos of long-running development machines. Born from a session where 23 stuck `bun test` processes and a 31GB Hyprland instance brought a 64-core machine to its knees.

---

## License

MIT - see [LICENSE](LICENSE) for details.

---

Built with bash, gum, and hard-won frustration. `pt` is designed to keep your machine running smoothly without manual process hunting.
