# AGENTS.md — Process Triage (pt)

## RULE 1 – ABSOLUTE (DO NOT EVER VIOLATE THIS)

You may NOT delete any file or directory unless I explicitly give the exact command **in this session**.

- This includes files you just created (tests, tmp files, scripts, etc.).
- You do not get to decide that something is "safe" to remove.
- If you think something should be removed, stop and ask. You must receive clear written approval **before** any deletion command is even proposed.

Treat "never delete files without permission" as a hard invariant.

---

## Project Overview

`pt` (Process Triage) is an interactive CLI for identifying and killing abandoned/zombie processes. It uses heuristics to score processes and learns from user decisions.

### Architecture

```
process_triage/
├── pt                  # Main executable (single file)
├── test/
│   └── pt.bats         # BATS test suite
├── README.md
├── AGENTS.md
└── LICENSE
```

### Key Design Decisions

1. **Bash-first**: No compiled dependencies, runs anywhere
2. **gum for UI**: Beautiful, consistent interactive components
3. **Learning memory**: JSON-based decision history with pattern normalization
4. **Safety by default**: Never auto-kills, always confirms, protects system services

---

## Development Guidelines

### Code Style

- Use `shellcheck` for all bash code
- Prefer `[[` over `[` for conditionals
- Quote all variables: `"$var"` not `$var`
- Use `local` for function variables
- Prefer `printf` over `echo` for portable output

### Testing

Tests use BATS (Bash Automated Testing System):

```bash
# Run all tests
bats test/

# Run specific test file
bats test/pt.bats

# Verbose output
bats --verbose-run test/
```

### Adding New Features

1. Write BATS tests first
2. Implement in appropriate lib file
3. Export function if needed in bin/pt
4. Update README if user-facing
5. Run `shellcheck bin/pt lib/*.sh`

---

## pt Quick Reference for AI Agents

Interactive process killer that identifies zombies using heuristics and learns from decisions.

### Core Commands

```bash
pt              # Interactive mode - scan, select, kill
pt scan         # Scan only - show candidates without killing
pt history      # Show past decisions
pt clear        # Clear decision memory
pt help         # Show help
```

### Key Concepts

| Concept | Description |
|---------|-------------|
| **Score** | 0-100+ rating of how suspicious a process is |
| **KILL** | Score >= 50, pre-selected for killing |
| **REVIEW** | Score 20-49, worth checking |
| **SPARE** | Score < 20, probably safe |
| **Pattern** | Normalized command used for learning |

### Process Detection

Detected as suspicious:
- Test runners (`bun test`, `jest`, `pytest`) running > 1 hour
- Dev servers (`next dev`, `vite`, `--hot`) running > 2 days
- Agent shells (`claude`, `codex`) running > 1 day
- Any orphaned process (PPID = 1)
- High memory + long age

Protected (never flagged):
- `systemd`, `dbus`, `sshd`, `cron`, `docker`

### Configuration

| File | Purpose |
|------|---------|
| `~/.config/process_triage/decisions.json` | Learned decisions |
| `~/.config/process_triage/triage.log` | Operation log |

### Safety Notes

- Always tries SIGTERM before SIGKILL
- Requires confirmation before any kill
- Logs all operations
- Never kills system services

---

## Troubleshooting

### Common Issues

**gum not found**: Run `pt` and it will auto-install, or:
```bash
sudo apt install gum  # Debian/Ubuntu
brew install gum      # macOS
```

**No candidates found**: System may be clean, or minimum age (1 hour) not reached.

**Decision memory not working**: Install jq:
```bash
sudo apt install jq
```

### Debug Mode

Set `PT_DEBUG=1` to see verbose output:
```bash
PT_DEBUG=1 pt scan
```

---

## Contributing to This Codebase

When modifying `pt`:

1. **Test changes**: Run `bats test/` before committing
2. **Check with shellcheck**: `shellcheck bin/pt lib/*.sh`
3. **Update docs**: If changing user-facing behavior, update README
4. **Preserve safety**: Never remove confirmation prompts or protected patterns
