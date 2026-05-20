# OSCAL Full Coverage & Validation Design

## Goal

Ensure the pipeline produces valid OSCAL artifacts covering all applicable framework layers, runs end-to-end with both inspector layers, and demonstrates the submission/validation workflow for the GRC Club workshop.

## OSCAL Layer Coverage

| Layer | Status | Approach |
|-------|--------|----------|
| Catalog | N/A | External reference (NIST 800-53 rev5) |
| Profile | N/A | External reference (FedRAMP Moderate baseline) |
| Component Definition | **Add** | New artifact, built dynamically across stages |
| SSP | **Fix** | Add roles/parties, fix states, fold in inventory |
| Assessment Plan | Skipped | Intentional — code IS the plan |
| Assessment Results | **Fix** | Add roles/parties, end timestamp, origins |
| POA&M | **Fix** | Add roles/parties, add origins to items |

## Implementation Sections

### Section 1: Structural Fixes

**All three produced artifacts (SSP, AR, POA&M):**
- Add `roles` array: `system-owner`, `authorizing-official`, `assessor`
- Add `parties` array: placeholder party entries referenced by roles
- These are required by the OSCAL schema

**SSP-specific:**
- Fix `by-components` implementation status: `"claimed"` -> proper OSCAL values (`"implemented"`, `"planned"`, `"partial"`)
- Converter sets initial states; assess/reconcile stages update them based on findings
- Fold `inventory.json` contents into `system-implementation.inventory-items`

**Assessment Results-specific:**
- Add `end` timestamp after assess stage completes
- Ensure observations/findings properly reference component UUIDs

**POA&M-specific:**
- Add `origins` array to each poam-item (traces back to assessment method)

### Section 2: Dynamic Component Definition

New artifact: `oscal/component-definition.json`

**Stage 1 (Convert):** Seeds component-definition from SSP keyword extraction. Components get `props` with `source: ssp-declared`.

**Stage 2 (Discover):** Adds newly found components not in SSP. Tags them `source: discovered`. Components claimed but not found get flagged. This is the "know more than what they tell you" moment.

**Stage 3 (Assess):** Assessment results link to component UUIDs via `related-observations`. Component status updated based on check results.

**Stage 4 (Reconcile):** POA&M items reference the component they relate to. Undeclared-but-discovered components become findings.

**Structure:**
```
component-definition
  metadata (with roles/parties)
  components[]
    uuid, type, title, description
    props[] (source: ssp-declared | discovered | both)
    control-implementations[]
      source (profile href)
      implemented-requirements[]
```

### Section 3: Submission Package & Validation

**Part A: OSCAL Validation**
- Integrate `oscal-cli validate` as a pipeline step (or flag)
- Validate each artifact: ssp.json, component-definition.json, assessment-results.json, poam.json
- Print pass/fail per file with schema errors

**Part B: Assessor View (enhance report.py)**
- Control summary: total controls, implemented/partial/planned, pass rate
- Component traceability: which components support which controls, declared vs. discovered
- Findings: observations mapped to controls with evidence sources
- POA&M: open items, severity, remediation status, linked to findings
- Drift detection: SSP claimed vs. discovery found

**Submission bundle:**
- Package all OSCAL artifacts into `submission/` folder with a manifest
- The "here's what you hand to your assessor" deliverable

### Section 4: Assessment — Two Layers

**Layer 1 (Pipeline tools):** Prowler, Trivy, AWS Config — surface-level posture checks. Is the tool there? Is it running?

**Layer 2 (Inspectors / GRClanker):** Deep component configuration assessment.
- `aws_inspector.py` — 8 check groups (root account, credentials, IAM policies, Access Analyzer, GuardDuty, Security Hub, S3 public access, CloudTrail org)
- `github_inspector.py` — 7 check groups (org settings, collaborators, branch protection, secret scanning, Dependabot, Actions, webhooks)
- Findings mapped to controls via `inspector_control_map.json`
- Run live during the demo against attendees' environments

**Integration:** Both inspectors output to `evidence/` directory. `import_inspector_findings()` in assess.py pulls them into OSCAL assessment results through the control map.

**Demo narrative:** "The pipeline found CloudTrail is enabled. The inspector asks the harder question — is it configured with log file validation? Is it encrypting with KMS? Is it logging management events across all regions? That's the difference between checking the box and proving the control."

## Demo Flow (60 min target)

1. **Convert** — SSP to OSCAL + seed component definition
2. **Discover** — What's actually in AWS, update component definition
3. **Assess Layer 1** — Prowler/Trivy/AWS Config surface checks
4. **Assess Layer 2** — Run inspectors live (AWS + GitHub deep checks)
5. **Reconcile** — SSP claims vs. reality, generate POA&M
6. **Enforce** — Pass/fail gate
7. **Report** — Assessor view, validate with oscal-cli, show submission package

## Files Modified

- `scripts/excel_to_oscal.py` / `docx_to_oscal.py` — roles/parties, component-definition output, fix states
- `scripts/discover.py` — update component-definition with discovered components
- `scripts/assess.py` — link findings to components, end timestamp
- `scripts/reconcile.py` — origins on POA&M items, component references
- `scripts/report.py` — enhanced assessor view
- `scripts/run_pipeline.py` — add validation step, submission bundle
- New: validation step using oscal-cli
