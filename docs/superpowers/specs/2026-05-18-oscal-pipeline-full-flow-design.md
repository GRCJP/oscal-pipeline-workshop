# OSCAL Pipeline — Full Flow Design

## Overview

Extend the oscal-pipeline-workshop from an SSP converter into a complete OSCAL compliance pipeline. The pipeline converts FedRAMP SSPs into OSCAL, discovers real infrastructure, assesses controls against live evidence, reconciles claims vs reality, and enforces compliance through gating and alerts.

Everything is Python scripts. Participants build and run each step locally. GitHub Actions are plumbing that runs the same scripts on a schedule — not the focus of the workshop.

## Pipeline Stages

```
SSP Template (Excel/Word)
    |
    v
1. CONVERT --> oscal/ssp.json                        [exists today]
    |
    v
2. DISCOVER --> oscal/inventory.json                  [new]
    |
    v
3. ASSESS                                             [new]
    |-- Control checks (Prowler, Trivy, NVD, CodeQL)
    |-- Tool inspector findings (pre-run grclanker output, imported)
    |
    v
4. RECONCILE --> oscal/assessment-results.json        [new]
             --> oscal/poam.json                      [new]
    |
    v
5. ENFORCE --> pass/fail gate + GitHub issue alert    [new]
```

## Stage 1: Convert (exists)

**Scripts:** `scripts/excel_to_oscal.py`, `scripts/docx_to_oscal.py`

Converts FedRAMP SSP templates (Excel or Word) into OSCAL JSON. Produces:
- `oscal/ssp.json` — System Security Plan (the claim)
- `oscal/assessment-results.json` — skeleton
- `oscal/poam.json` — skeleton

The converter infers each control's evidence method automatically based on the tool registry:
- 2+ tools can verify → automated
- 1 tool can verify → hybrid (tool evidence + human review)
- 0 tools → manual
- Inherited → stays inherited

No changes needed. This stage is complete.

## Stage 2: Discover

**Script:** `scripts/discover.py`

Pulls a real inventory from AWS and GitHub, then compares it to what the SSP claims.

### Data sources

- **AWS Config:** `list_discovered_resources` across us-east-1 — IAM users, S3 buckets, CloudTrail trails, Config recorders, EC2 instances, etc.
- **GitHub API:** repositories, branch protection settings, Actions workflows

### Output

`oscal/inventory.json` — OSCAL-formatted component inventory containing every discovered resource.

### Drift detection

Compares discovered inventory against the SSP's declared components:
- Resources in AWS/GitHub but not in SSP → flagged as undocumented
- Resources in SSP but not in AWS/GitHub → flagged as missing

These gaps feed into the reconcile step.

## Stage 3: Assess

**Script:** `scripts/assess.py`

Two types of evidence, handled the same way: run or read, capture output, render screenshot, map to controls, write findings.

### Control-specific checks (run live)

| Tool | What it checks | Controls |
|------|---------------|----------|
| Prowler | AWS security posture (IAM, S3, CloudTrail, etc.) | AC, AU, SC, CP |
| Trivy | Container/IaC/dependency vulnerabilities | RA, SI, SA |
| NVD API | CVE lookup against discovered components | RA-5, SI-2 |
| CodeQL | Pull results from GitHub Actions (already runs via workflow) | SA-11 |

For each check:
1. Run the tool
2. Capture CLI output as text
3. Render text to PNG using Pillow with monospace font
4. Save to `evidence/screenshots/{control}-{tool}-{timestamp}.png`
5. Parse findings, map each to OSCAL control(s)
6. Tag with source (e.g., `"source": "prowler"`)

### Tool inspector findings (pre-run, imported)

grclanker inspector output already exists as JSON files placed in the evidence directory:
- `evidence/aws-inspector-findings.json`
- `evidence/github-inspector-findings.json`

These are not run by the pipeline. The user ran grclanker separately and dropped the output files in. The pipeline treats them as another evidence source.

For each finding:
1. Read the JSON
2. Map to OSCAL control(s) using `scripts/inspector-control-map.json`
3. Render finding detail to PNG screenshot
4. Tag with `"source": "aws-sec-inspector"` or `"github-sec-inspector"`

### Inspector control mapping

`scripts/inspector-control-map.json` is a manually curated config that maps inspector finding types to OSCAL controls. Example:

```json
{
  "stale_access_key": ["AC-2"],
  "no_mfa": ["IA-2"],
  "guardduty_disabled": ["SI-4"],
  "cloudtrail_not_multiregion": ["AU-2", "AU-3"],
  "branch_protection_disabled": ["CM-3"],
  "no_required_reviews": ["CM-3", "SA-11"]
}
```

This is the only piece that requires manual curation.

### Screenshot capture

Every check — pass or fail — gets a CLI output screenshot. The screenshot is a PNG rendering of the terminal output at the time of the check.

Process:
1. Capture CLI stdout/stderr as text
2. Render to PNG using Python Pillow with a monospace font (Courier or similar)
3. Save to `evidence/screenshots/` with naming convention: `{control}-{tool}-{timestamp}.png`
4. Reference the screenshot path in the finding entry in assessment-results.json

Evidence directory structure:
```
evidence/
  screenshots/
    AC-2-prowler-2026-05-18T14-30-00.png
    AC-2-aws-sec-inspector-2026-05-18T14-30-00.png
    RA-5-trivy-2026-05-18T14-31-00.png
    CM-3-github-sec-inspector-2026-05-18T14-31-00.png
  aws-inspector-findings.json
  github-inspector-findings.json
```

## Stage 4: Reconcile

**Script:** `scripts/reconcile.py`

Compares SSP claims against assessment evidence. Produces the final OSCAL artifacts.

### Input

- `oscal/ssp.json` — what the SSP claims
- All findings from assess.py (control checks + inspector findings, tagged by source)
- `oscal/inventory.json` — discovered components

### Logic

For each control in the SSP:
1. Gather all findings mapped to that control, across all sources
2. Compare SSP claimed status against evidence:
   - SSP says "implemented" + evidence confirms → **pass**
   - SSP says "implemented" + evidence contradicts → **fail** → POA&M item
   - SSP says "implemented" + no evidence exists → **gap** → POA&M item (unverified claim)
   - Undocumented component touches this control → **gap** → POA&M item
3. Record reconciliation result with all contributing sources

### Output

**`oscal/assessment-results.json`** — populated with:
- Every finding tagged by source and control
- Reconciliation status per control: confirmed, contradicted, or unverified
- Screenshot references for each finding

**`oscal/poam.json`** — populated with:
- One POA&M item per gap or failure
- Source attribution (which tool or inspector found it)
- Reference to the SSP control and contradicting evidence

## Stage 5: Enforce

**Script:** `scripts/enforce.py`

A Python script like everything else. Participants run it locally first.

### Usage

```bash
python3 scripts/enforce.py --results oscal/assessment-results.json --poam oscal/poam.json
```

### Behavior

1. Reads assessment-results.json and poam.json
2. Checks for new or unresolved findings
3. Prints pass/fail summary to console
4. Exit code 0 (all clear) or 1 (findings exist)
5. If failures exist, uses GitHub API to open an issue:
   - Title: `[Pipeline] {N} new findings — {date}`
   - Body: summary table of findings, affected controls, screenshot references

### CI integration

GitHub Actions workflows call the same Python scripts:

- **`oscal-validation.yml` (existing, extended):** triggers on PR/push, runs converter + validation + enforce.py as CI gate
- **`full-assessment.yml` (new):** triggers on weekly schedule + `workflow_dispatch` for live demo, runs the full pipeline (discover → assess → reconcile → enforce), commits updated artifacts and evidence to the repo

The YAML is plumbing. The workshop teaches the Python scripts.

## Pipeline Runner

**Script:** `scripts/run_pipeline.py`

Calls all 5 stages in sequence with clear stage banners. Used for the end-to-end demo after participants have learned each script individually.

Participants learn by running scripts one by one. The runner ties it together at the end to show the full flow start to finish.

The runner calls the same scripts — no duplicate logic.

## Workshop Flow

1. **Teach each stage** — presenter runs each script individually, explains what it does and why
2. **Full run** — presenter runs `run_pipeline.py` to show the complete pipeline end-to-end
3. **Trigger CI** — presenter triggers `full-assessment.yml` via `workflow_dispatch` to show enforcement in CI

## File Summary

### New scripts
| File | Purpose |
|------|---------|
| `scripts/discover.py` | Pull AWS Config + GitHub inventory, produce OSCAL inventory, detect drift |
| `scripts/assess.py` | Run control checks, import inspector findings, capture screenshots, map to controls |
| `scripts/reconcile.py` | Diff SSP claims vs evidence, produce assessment-results and POA&M |
| `scripts/enforce.py` | Pass/fail gate, open GitHub issue on failures |
| `scripts/inspector-control-map.json` | Maps grclanker inspector finding types to OSCAL controls |
| `scripts/run_pipeline.py` | End-to-end runner — calls all stages in sequence with stage banners |

### New directories
| Directory | Purpose |
|-----------|---------|
| `evidence/` | Inspector finding JSON files (user-provided) |
| `evidence/screenshots/` | CLI output screenshots (pipeline-generated) |

### New dependencies
| Package | Purpose |
|---------|---------|
| `Pillow` | Render CLI text output to PNG screenshots |
| `boto3` | AWS Config and IAM API calls for discovery |
| `requests` | NVD API lookups |

### Modified files
| File | Change |
|------|--------|
| `oscal-validation.yml` | Add enforce.py as CI gate step |
| `full-assessment.yml` | New workflow: scheduled + manual full pipeline run |
