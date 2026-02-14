# Examples

All examples are safe by default (scan/plan only). Do not run apply commands unless you have reviewed the evidence and understand the risks.

Contents:
- scan_only.sh: quick scan in JSON
- agent_plan_only.sh: plan-only JSON output
- priors.example.json: minimal priors file (schema 1.0.0)
- policy.example.json: validated policy example (server-oriented baseline)
- redaction.example.json: minimal redaction policy
- signatures.example.json: signature schema v2 example
- configs/: scenario-tuned policy/discovery examples (developer, server, ci, fleet)

Bundle/report examples (manual):

```bash
# Requires an existing session in the session store
pt bundle create --session <session-id> --output /tmp/session.ptb --profile safe
pt report --session <session-id> --output /tmp/pt-report.html
```

Scenario configs:

```bash
pt-core config validate examples/configs/developer.json --format summary
pt-core config validate examples/configs/server.json --format summary
pt-core config validate examples/configs/ci.json --format summary
```
