# Pipeline Reports — Design Spec

## Overview

Add a report stage to the pipeline that produces three outputs after enforce: an HTML executive dashboard, an updated SSP Excel export, and a POA&M Excel export. Linear integration is a fourth output built separately.

## Output 1: HTML Dashboard (`scripts/report.py`)

**Input:** `oscal/ssp.json`, `oscal/assessment-results.json`, `oscal/poam.json`, `oscal/inventory.json`

**Output:** `oscal/report.html` — standalone HTML with inline CSS, opens in any browser.

### Sections

**Executive Summary (top):**
- System name, baseline (FedRAMP Moderate), date of run
- Verdict breakdown: confirmed, contradicted, manual-review, inherited, undocumented — displayed as colored count boxes
- Total checks run, passed, failed
- Total POA&M items

**Drift Detection:**
- Three-column layout: Documented (green), Undocumented (red), Missing (yellow)
- Each lists the service names

**Failed Checks:**
- Table grouped by control family (AC, AU, CM, IA, SC, SI, SA)
- Columns: Control, Source, Finding, Status
- Failed rows highlighted red, passed rows green

**POA&M Items:**
- Table of all POA&M items
- Columns: Control ID, Finding, Source, Description, Date Found
- Only contradicted and undocumented items (not manual-review)

### Styling
- Dark professional theme (dark background, light text)
- Monospace font for data
- Color coding: green = pass/confirmed, red = fail/contradicted, yellow = manual-review, gray = inherited, orange = undocumented
- No JavaScript required — pure HTML + inline CSS
- Responsive — readable on any screen size

### Usage
```bash
python3 scripts/report.py --ssp oscal/ssp.json --results oscal/assessment-results.json --poam oscal/poam.json --inventory oscal/inventory.json --output oscal/report.html
```

## Output 2: Updated SSP Export (`scripts/export_ssp.py`)

**Input:** `oscal/ssp.json`, `oscal/assessment-results.json`

**Output:** `oscal/updated-ssp.xlsx` — new Excel file reflecting pipeline results.

### Columns
Same structure as the input template, with updated/added columns:
- Col 1-6: Unchanged (No., Family, Control ID, Control Name, Control Text, Related)
- Col 7: Implementation Status — unchanged from SSP
- Col 8: Evidence Method — updated based on actual assessment results (automated/hybrid/manual)
- Col 9: Implementation Description — unchanged from SSP
- Col 10 (new): Reconciliation Verdict — confirmed/contradicted/manual-review/inherited
- Col 11 (new): Last Reconciled — date of this pipeline run
- Col 12 (new): Components Found — components extracted from narrative + discovered
- Col 13 (new): Findings — summary of any failed checks for this control

Does NOT overwrite the original template. Produces a new file for comparison.

### Usage
```bash
python3 scripts/export_ssp.py --ssp oscal/ssp.json --results oscal/assessment-results.json --template Templates/fedramp-moderate-template-ssp.xlsx --output oscal/updated-ssp.xlsx
```

## Output 3: POA&M Excel Export (`scripts/export_poam.py`)

**Input:** `oscal/poam.json`

**Output:** `oscal/poam-report.xlsx`

### Columns
- Col A: POA&M ID (sequential)
- Col B: Control ID
- Col C: Finding
- Col D: Source
- Col E: Description
- Col F: Status (open)
- Col G: Date Found
- Col H: Severity (derived from control family priority)
- Col I: Recommended Action

### Styling
- Header row bold with background color
- Alternating row colors for readability
- Auto-fit column widths

### Usage
```bash
python3 scripts/export_poam.py --poam oscal/poam.json --output oscal/poam-report.xlsx
```

## Output 4: Linear Integration (`scripts/export_to_linear.py`)

**Deferred to next session.** Will push POA&M items as Linear issues.

## Pipeline Integration

`run_pipeline.py` updated to call report scripts after enforce:

```
Stage 1: Convert
Stage 2: Discover
Stage 3: Assess
Stage 4: Reconcile
Stage 5: Enforce
Stage 6: Report  ← new
  ├─ report.html
  ├─ updated-ssp.xlsx
  └─ poam-report.xlsx
```

New flags on `run_pipeline.py`:
- `--report` (default on) — generate HTML dashboard
- `--export-ssp` (default on) — generate updated SSP Excel
- `--export-poam` (default on) — generate POA&M Excel
- `--linear` (default off) — push to Linear (opt-in)

## New Files

| File | Purpose |
|---|---|
| `scripts/report.py` | Generate HTML executive dashboard |
| `scripts/export_ssp.py` | Generate updated SSP Excel with pipeline results |
| `scripts/export_poam.py` | Generate POA&M Excel report |
| `scripts/export_to_linear.py` | Push POA&M to Linear (deferred) |

## Dependencies

No new dependencies. Uses openpyxl (already installed) for Excel output and Python string formatting for HTML.
