# Demo Scripts and Recording References

This directory tracks three short demo workflows intended for asciinema/terminal recording.

## Demo Set

- `docs/demos/basic-scan.sh` (about 30s)
  - Scan and summarize suspicious candidates.
- `docs/demos/plan-review-apply.sh` (about 60s)
  - Create a session, verify recommendations, and run dry-run apply.
- `docs/demos/robot-mode.sh` (about 45s)
  - Show machine-oriented output modes (`toon`, compact fields, dry-run).

## Recording Workflow

```bash
# Example asciinema recording commands
asciinema rec -c "bash docs/demos/basic-scan.sh" docs/demos/basic-scan.cast
asciinema rec -c "bash docs/demos/plan-review-apply.sh" docs/demos/plan-review-apply.cast
asciinema rec -c "bash docs/demos/robot-mode.sh" docs/demos/robot-mode.cast
```

## Publishing Notes

- Keep cast files redaction-safe before upload.
- Link published recordings from README once available.
