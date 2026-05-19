# Discovery-Driven Pipeline Refactor — Design Spec

## Problem

The current pipeline uses a hardcoded `TOOL_REGISTRY` that pre-maps tools to controls and pre-computes evidence methods. This creates three problems:

1. **It assumes what should be discovered.** The registry defines which tools exist and what they prove before the pipeline ever checks the environment. If the registry is wrong (e.g., GitHub missing from AC controls), the pipeline has blind spots from the start.
2. **It's not OSCAL-native.** OSCAL Component Definitions describe what tools/services exist and what controls they satisfy. The registry duplicates this concept outside of OSCAL.
3. **It doesn't solve the real problem.** Organizations don't know what they don't know. A predefined list of tools can't find the KMS key nobody documented, the security group nobody claimed, or the service that was decommissioned last quarter.

## Solution

Remove the tool registry. Make discovery the source of truth for what exists in the environment. The pipeline becomes:

1. **Convert** — reads the SSP as-is. Extracts components mentioned in narratives via keyword matching. No assumptions about what tools should exist or what controls they map to.
2. **Discover** — queries the actual environment (AWS, GitHub). Builds the real component inventory. Compares against what the SSP claimed. Flags drift: undocumented resources, missing resources.
3. **Assess** — runs checks based on what discovery found. Evidence method is determined by results, not predicted.
4. **Reconcile** — compares SSP claims against evidence. Undocumented resources become POA&M items.
5. **Enforce** — gates and alerts on findings.

## OSCAL Model Alignment

| OSCAL Model | Pipeline Stage | How It's Built |
|---|---|---|
| Model 1: Catalog | Referenced | NIST 800-53 Rev 5 (we point to it) |
| Model 2: Profile | Referenced | FedRAMP Moderate baseline (we point to it) |
| Model 3: Component Definition | Convert + Discover | Converter extracts SSP-claimed components. Discovery adds what's actually there. Built progressively, not upfront. |
| Model 4: SSP | Convert | The claim — controls, status, narratives, and whatever components the SSP mentions. |
| Model 5: Assessment Plan | Not produced | The code is the plan. Scripts define what's checked and how. Explained in workshop as automating the plan, not skipping it. |
| Model 6: Assessment Results | Assess + Reconcile | Assess collects evidence. Reconcile adds verdicts. |
| Model 7: POA&M | Reconcile | Gaps and contradictions become action items. |

## Stage 1: Convert (refactored)

### What stays the same
- Reads Excel/Word SSP template
- Extracts control ID, status, narrative
- Produces `oscal/ssp.json`, skeleton `assessment-results.json`, skeleton `poam.json`
- Deterministic UUIDs, banner output

### What changes
- `TOOL_REGISTRY` removed entirely
- No `by-components` pre-mapping to controls
- No evidence method inference — determined after assessment
- New: keyword scan of each control's narrative to extract component mentions

### Keyword matching

A dictionary of known tool/service names used for name recognition only. It does NOT map tools to controls or define what they prove. It just recognizes names so the converter can say "the SSP mentions this tool for this control."

```python
KNOWN_COMPONENTS = {
    "aws iam": {"title": "AWS IAM", "type": "service"},
    "aws s3": {"title": "AWS S3", "type": "service"},
    "aws kms": {"title": "AWS KMS", "type": "service"},
    "aws cloudtrail": {"title": "AWS CloudTrail", "type": "service"},
    "aws config": {"title": "AWS Config", "type": "service"},
    "aws cloudwatch": {"title": "AWS CloudWatch", "type": "service"},
    "github": {"title": "GitHub", "type": "software"},
    "github actions": {"title": "GitHub Actions", "type": "software"},
    "codeql": {"title": "CodeQL", "type": "software"},
    "trivy": {"title": "Trivy", "type": "software"},
    "prowler": {"title": "Prowler", "type": "software"},
    "jenkins": {"title": "Jenkins", "type": "software"},
    "splunk": {"title": "Splunk", "type": "software"},
    "okta": {"title": "Okta", "type": "service"},
    "azure ad": {"title": "Azure AD", "type": "service"},
    "duo": {"title": "Duo", "type": "service"},
}
```

### Output per control

- If narrative mentions a known component → create a `by-component` entry with `"state": "claimed"` and `"remarks": "referenced in SSP narrative"`
- If narrative mentions no tools → no by-components. It's a policy/manual control as far as the SSP is concerned.

### Component section

- Only components actually found in narratives get added to `system-implementation.components`
- Plus `"this-system"` as required by OSCAL
- Each extracted component is tagged `"origin": "ssp-narrative"` so discovery can distinguish SSP-claimed components from discovered ones

### Summary output

```
AC-2    implemented    components: aws iam, github    ✓ narrative
AC-8    implemented    components: (none)             ✓ narrative
RA-5    implemented    components: prowler, trivy     ✓ narrative

Components extracted from SSP narratives: 5
  AWS IAM, GitHub, Prowler, Trivy, AWS CloudTrail
```

## Stage 2: Discover (refactored)

### What stays the same
- Queries AWS Config for resources in us-east-1
- Queries GitHub API (scoped to single repo)
- Produces `oscal/inventory.json`
- Screenshot capture

### What changes

Discovery now builds the real component inventory. Every resource it finds becomes an OSCAL component. It also dynamically detects additional resource types beyond what was originally queried.

### Drift detection

Compares SSP-declared components (from converter's keyword extraction) against what's actually in the environment:

- **Documented** — component in SSP AND found in environment
- **Undocumented** — found in environment but NOT mentioned in SSP (blind spot)
- **Missing** — mentioned in SSP but NOT found in environment (stale claim)

### Output

```
DRIFT DETECTION
═══════════════
Documented (SSP + environment):     3  (AWS IAM, GitHub, CloudTrail)
Undocumented (environment only):    4  (KMS key, security group, VPC, S3 open bucket)
Missing (SSP only):                 1  (Jenkins — claimed but not found)
```

### Continuous lifecycle

When the pipeline runs on a schedule, discovery catches changes over time:
- New resources spun up → flagged as undocumented
- Decommissioned tools → flagged as missing
- The drift summary shows what changed since last run

## Stage 3: Assess (refactored)

### What stays the same
- Direct AWS checks: IAM, S3, CloudTrail, security groups, VPC flow logs, KMS rotation, S3 TLS
- GitHub checks: branch protection, code scanning
- Prowler, Trivy, NVD as optional tools
- Inspector findings import (grclanker)
- Screenshot capture
- Control mapping for each finding

### What changes

- No reference to `TOOL_REGISTRY` anywhere
- Evidence method determined by results:
  - Control has findings from 2+ sources → automated
  - Control has findings from 1 source → hybrid
  - Control has 0 findings → manual
  - Inherited → stays inherited
- Assessment reads `oscal/inventory.json` to know what was discovered
- Findings from undocumented resources tagged with `"undocumented-resource": true`

## Stage 4: Reconcile (minimal changes)

- Now flags undocumented resources as POA&M items: "KMS key exists in environment but SSP doesn't mention it"
- Evidence method per control written based on actual assessment results
- Everything else stays the same

## Stage 5: Enforce (no changes)

- Reads assessment-results and POA&M
- Gates and alerts
- No changes needed

## Files Changed

| File | Change |
|---|---|
| `scripts/excel_to_oscal.py` | Remove `TOOL_REGISTRY`, add keyword extraction from narratives, remove `by-components` pre-mapping, remove `infer_evidence_method` |
| `scripts/docx_to_oscal.py` | Same changes as excel converter |
| `scripts/pipeline_utils.py` | Remove `TOOL_REGISTRY`, remove `get_tools_for_control`, keep screenshot capture and OSCAL helpers |
| `scripts/discover.py` | Build component list dynamically, real drift detection (documented/undocumented/missing) |
| `scripts/assess.py` | Remove registry references, determine evidence method from results, tag undocumented resource findings |
| `scripts/reconcile.py` | Flag undocumented resources as POA&M items, write evidence method from actual results |
| `scripts/run_pipeline.py` | No changes |
| `scripts/enforce.py` | No changes |

## SSP Template Updates

The Excel and Word SSP templates should have component references sprinkled in some control narratives but not all. This makes the demo realistic:

- AC-2: mentions AWS IAM for account management
- AU-2: mentions CloudTrail for audit logging
- CM-3: mentions GitHub for change management
- RA-5: mentions Prowler and Trivy for vulnerability scanning
- SC-28: mentions AWS S3 for encryption at rest
- Many controls: no tool mentioned — pure policy/process narrative

This mix lets the converter extract some components and miss others, which discovery then fills in.
