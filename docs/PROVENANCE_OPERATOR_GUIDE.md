# Provenance Operator Guide

Provenance tells you **why a process exists**, **why pt thinks it's suspicious**, **what would break if you kill it**, and **what pt doesn't know**.

## What You See

### CLI (`pt scan`, `pt agent plan`)

Each candidate includes a provenance section in the output:

```
Provenance: low blast radius; strong evidence
  🔗 Provenance Signals: orphaned (no parent); low blast radius
  🛡 Blast Radius: Low risk (score 15%). Isolated process, no shared resources
  ⚠ Caveats: missing lineage provenance
```

### JSON/TOON output

The `provenance_inference` field in each candidate contains the machine-readable contract:

```json
{
  "enabled": true,
  "evidence_completeness": 0.85,
  "confidence_penalty_steps": 1,
  "confidence_notes": ["resource provenance has 2 unresolved edge(s)"],
  "score_terms": ["provenance_ownership_orphaned", "provenance_blast_radius_low"],
  "blast_radius": {
    "risk_score": 0.12,
    "risk_level": "low",
    "confidence": 0.90,
    "summary": "Isolated process with no shared resources",
    "total_affected": 0
  },
  "redaction_state": "none",
  "score_impact": {
    "log_odds_shift": 0.35,
    "feature_contributions": [...]
  }
}
```

### TUI

Press `p` in the detail view to switch to the Provenance inspector. It shows:
- Evidence signals with human-readable labels
- Blast-radius risk badge (color-coded: red=critical/high, yellow=medium)
- Caveats count

### Reports

HTML reports include `provenance_headline`, `blast_radius_risk`, and `blast_radius_affected` for each candidate.

### Daemon alerts

Trigger alerts include `provenance_context` hints showing which processes contributed to the spike and their blast-radius risk.

### Fleet scans

Per-host results include `provenance` summaries with evidence completeness and risk distribution. Fleet-wide aggregates show how many hosts had provenance available.

## Understanding Confidence

Evidence completeness ranges from 0.0 (no evidence) to 1.0 (all probes ran):

| Completeness | Label | Meaning |
|---|---|---|
| >= 0.9 | strong | All expected probes ran; assessment is reliable |
| 0.7-0.9 | moderate | Minor gaps; conclusion is likely correct |
| 0.5-0.7 | partial | Significant gaps; treat assessment with caution |
| < 0.5 | weak | Insufficient evidence; blast radius is uncertain |

Each confidence gap adds a **penalty step** that downgrades the displayed confidence tier (VeryHigh -> High -> Medium -> Low).

## Understanding Blast Radius

| Risk Level | Meaning | Automation |
|---|---|---|
| low | Isolated process, minimal impact | Auto-kill allowed |
| medium | Some shared resources or children | Auto-kill allowed |
| high | Significant dependents or services | Requires confirmation |
| critical | Listeners + dependents, or >4GB | Auto-kill blocked |

## Redaction

Provenance may be partially or fully redacted per the privacy policy. The `redaction_state` field tells you:

- `none`: All evidence available
- `partial`: Some evidence was redacted (specific paths, IPC details)
- `full`: All provenance evidence was redacted

When evidence is redacted, caveats explain what was withheld and why.

## Troubleshooting

**"Provenance: not available"**: Provenance is disabled or the platform doesn't support it (non-Linux). Check `provenance.posture` in your config.

**Low evidence completeness**: Some probes couldn't run. Common causes:
- Missing `/proc` access (containers)
- `lsof`/`ss` not available (affects resource collection)
- Privacy policy is strict (redacts evidence before scoring)

**Unexpected blast radius**: If a process shows high risk but you know it's safe, check the `confidence_notes` for evidence gaps that inflated the risk estimate.

**Debug logging**: Set `RUST_LOG=pt_core=trace` to see per-feature provenance evidence selection:
```
provenance_evidence_selected pid=1234 feature=provenance_ownership_orphaned net_shift=1.25 direction=toward_abandon
provenance_confidence_downgraded pid=1234 steps=2 reasons=["missing lineage", "2 unresolved edges"]
provenance_blast_radius_computed pid=1234 risk_score=0.82 risk_level=High total_affected=8
```

## Performance Budgets

Provenance has per-context time budgets to avoid blocking scans:

| Context | Total Budget | Degradation Strategy |
|---|---|---|
| Quick scan | 200ms | Skip narrative, then blast radius, then resources |
| Deep scan | 2000ms | Full provenance |
| Daemon | 100ms | Skip narrative + blast radius first |
| Fleet | 500ms | Skip narrative, then blast radius |

When budgets are exceeded, provenance degrades gracefully rather than blocking.
