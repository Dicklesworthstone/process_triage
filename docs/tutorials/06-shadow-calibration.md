# Tutorial 06: Shadow Mode (Observe, Never Act)

Goal: Record what pt would recommend over time, without acting, and read the report.

## 1) Start the observer in the background

```bash
pt shadow start --background --interval 300
pt shadow status
```

The observer runs `agent plan` every `--interval` seconds and records each
recommendation. It never executes an action.

## 2) Label processes you have independently reviewed

After the observer has recorded a process, give your own judgment while that
process is still running:

```bash
pt agent label --pid <abandoned-pid> --kill
pt agent label --pid <useful-pid> --spare
```

These commands record judgments; they do not kill or otherwise change the process.
They update the command pattern's learned prior and persist a separate human
verdict for shadow calibration. The report pairs that verdict with the latest
earlier prediction for the same process incarnation, including its start identity.
It never pairs by PID alone, invents a prediction for an unseen process, or applies
an earlier verdict to later predictions made with the learned prior. Each process
incarnation can contribute at most one explicit calibration label. If you label
before its first observation, that incarnation supplies no calibration sample:
repeating the label cannot evaluate a prediction that already learned from it.

`--cmd` labels still teach command patterns, but have no process identity and
therefore do not label shadow predictions. TUI judgments currently teach pattern
priors; use explicit `agent label --pid` judgments for shadow calibration.

## 3) Read the report

```bash
pt shadow report -f md
```

The report calibrates P(abandoned or zombie), the same probability used for the
suspicion score. Read `positive_labels` and `negative_labels` in
`pt shadow report --format json` first: metrics remain unavailable until each class
has at least five explicit labels. An exit, crash, disappearance, or external kill
alone does not prove whether work was useful and remains unlabeled. This sample
minimum enables reporting; it does not establish a fleet-wide false-kill guarantee.
With `shadow report --limit`, older human verdicts remain as context so limiting
the observation window cannot make repeated labels count as independent evidence.
`shadow export --limit` continues to limit the number of raw exported records.

The verdict is persisted before the learned prior is updated, so calibration does
not evaluate the model against a label it already learned from. If verdict storage
fails, the label command reports an error and leaves the learned prior unchanged.
If the subsequent prior save fails, it reports that the shadow verdict was retained.

## 4) Stop the observer

```bash
pt shadow stop
```

Notes:
- Shadow observations live in pt's data directory; `pt shadow export` writes them out
  for your own analysis.
- What teaches pt directly is a verdict you give: `pt agent label --pid <pid> --kill`
  or `--spare` (or a kill you confirm in the TUI).
