# Scenario Configurations

This directory contains validated configuration examples for common deployment styles.

## Files

- `developer.json`: aggressive preset for development machines.
  - Lower confidence thresholds and higher cleanup tolerance.
  - Useful when long-running tests/dev servers accumulate frequently.
- `server.json`: conservative preset for production/server hosts.
  - Stronger safety gates and stricter blast-radius limits.
  - Preferred default for persistent hosts and shared environments.
- `ci.json`: headless-friendly preset for CI/CD automation.
  - Robot-oriented safety constraints and deterministic output behavior.
  - Suitable for scripted plan/verify/apply workflows.
- `fleet.json`: fleet discovery configuration for multi-host planning.
  - Uses static inventory provider to keep behavior reproducible.
  - Includes cache and refresh controls for coordinator polling.
- `fleet.inventory.json`: sample static fleet inventory consumed by `fleet.json`.

## Validate Examples

```bash
# Validate policy presets
pt-core config validate examples/configs/developer.json --format summary
pt-core config validate examples/configs/server.json --format summary
pt-core config validate examples/configs/ci.json --format summary

# Validate discovery + inventory JSON structure
jq -e '.providers | length > 0' examples/configs/fleet.json >/dev/null
jq -e '.hosts | length > 0' examples/configs/fleet.inventory.json >/dev/null
```

## Usage Notes

- The first three files are exported from built-in presets (`pt-core config export-preset ...`) to keep them in sync with schema changes.
- `fleet.json` is intentionally static-provider based so it remains safe for local docs/testing without cloud dependencies.
