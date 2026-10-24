# Tutorial 06: Shadow Mode (Observe, Never Act)

Goal: Record what pt would recommend over time, without acting, and read the report.

## 1) Start the observer in the background

```bash
pt shadow start --background --interval 300
pt shadow status
```

The observer runs `agent plan` every `--interval` seconds and records each
recommendation. It never executes an action.

## 2) Let it run, then read the report

```bash
pt shadow report -f md
```

The report lines up recorded recommendations with what later happened to each
process. Read the label counts first: until there are enough outcomes of both kinds
(processes that turned out abandoned and ones that did not), the calibration figures
say little.

## 3) Stop the observer

```bash
pt shadow stop
```

Notes:
- Shadow observations live in pt's data directory; `pt shadow export` writes them out
  for your own analysis.
- What teaches pt directly is a verdict you give: `pt agent label --pid <pid> --kill`
  or `--spare` (or a kill you confirm in the TUI).
