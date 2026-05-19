# Discovery-Driven Pipeline Refactor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the hardcoded tool registry and make discovery the source of truth. The converter reads what the SSP says. Discovery finds what's actually there. Assessment tests it. No assumptions.

**Architecture:** The TOOL_REGISTRY is removed from all scripts. The converter scans SSP narratives for component mentions via keyword matching (name recognition only, no control mapping). Discovery dynamically builds the component inventory from AWS Config + GitHub. Assessment determines evidence method from actual results. Reconciliation flags undocumented resources as POA&M items.

**Tech Stack:** Python 3.10+, openpyxl, python-docx, boto3, requests, Pillow (all existing)

---

### Task 1: Update SSP Excel template with tool mentions in narratives

**Files:**
- Modify: `Templates/fedramp-moderate-template-ssp.xlsx`

The current narratives are generic ("identity governance platform", "centralized SIEM"). Some controls need specific tool names so the keyword extractor has something to find. Most controls stay generic — that's realistic.

- [ ] **Step 1: Update narratives in the Excel template**

Open the Excel file and update column 9 (Implementation Description) for these controls:

| Control | Current narrative starts with | Add to narrative |
|---|---|---|
| AC-2 | "The system enforces account management through an identity governance platform..." | Change to: "The system enforces account management through AWS IAM. All user accounts require manager approval before provisioning. Accounts are reviewed quarterly and disabled after 90 days of inactivity. Service accounts are inventoried and rotated on schedule." |
| AU-2 | "The system logs all authentication events..." | Change to: "The system logs all authentication events, authorization decisions, and administrative actions through AWS CloudTrail. Logs are forwarded to a centralized SIEM. Log retention meets the minimum 12-month requirement with 90 days immediately available." |
| CM-3 | "All changes to production require a change request ticket..." | Change to: "All changes to production are managed through GitHub with branch protection and required pull request reviews. Changes are tested in staging before production. Emergency changes follow an expedited approval with post-implementation review." |
| RA-5 | "Vulnerability scans are performed continuously..." | Change to: "Vulnerability scans are performed continuously using Prowler for cloud security posture and Trivy for container and dependency scanning. Critical vulnerabilities remediated within 15 days, high within 30 days. Scan results correlated with asset inventory for coverage validation." |
| SC-28 | "All data at rest is encrypted using AES-256..." | Change to: "All data at rest is encrypted using AES-256 through AWS S3 server-side encryption and AWS KMS for key management. Encryption is enforced at the storage layer. Unencrypted storage resources are flagged as non-compliant." |
| SI-4 | "Continuous monitoring through SIEM integration..." | Change to: "Continuous monitoring through AWS CloudWatch and VPC Flow Logs. Network traffic analysis detects anomalous patterns. Security operations reviews alerts daily. Critical alerts trigger automated incident creation." |

Leave all other controls as-is — their generic narratives are intentional. The converter should show "(none)" for components on those controls.

Run: `python3 scripts/excel_to_oscal.py --input Templates/fedramp-moderate-template-ssp.xlsx --output /tmp/test-pre-refactor` to verify the template still converts cleanly.

Expected: 57 controls, CONVERSION COMPLETE (existing converter, before refactor).

- [ ] **Step 2: Commit**

```bash
git add Templates/fedramp-moderate-template-ssp.xlsx
git commit -m "chore: add tool mentions to SSP narratives for keyword extraction

AC-2 mentions AWS IAM, AU-2 mentions CloudTrail, CM-3 mentions
GitHub, RA-5 mentions Prowler/Trivy, SC-28 mentions S3/KMS,
SI-4 mentions CloudWatch. Other controls stay generic."
```

---

### Task 2: Refactor pipeline_utils.py — remove TOOL_REGISTRY, add KNOWN_COMPONENTS

**Files:**
- Modify: `scripts/pipeline_utils.py`

- [ ] **Step 1: Replace TOOL_REGISTRY with KNOWN_COMPONENTS and add extract_components_from_text**

Replace the entire `scripts/pipeline_utils.py` with:

```python
"""
pipeline_utils.py — Shared constants and helpers for the OSCAL pipeline.

Every pipeline script imports from here instead of duplicating
OSCAL_NAMESPACE, stable_uuid, and screenshot capture.
"""

import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ── UUID v5 deterministic identifiers ─────────────────────────────────────────
OSCAL_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

def stable_uuid(name: str) -> str:
    return str(uuid.uuid5(OSCAL_NAMESPACE, name))

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def now_filesafe() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")


# ── Known Components (name recognition only) ─────────────────────────────────
# This is NOT a registry. It does NOT map tools to controls or define what
# they prove. It just recognizes tool/service names in SSP narratives so the
# converter can say "the SSP mentions this tool for this control."
#
# Discovery finds what's actually in the environment — that's the real inventory.

KNOWN_COMPONENTS = {
    "aws iam":          {"title": "AWS IAM",          "type": "service"},
    "aws s3":           {"title": "AWS S3",           "type": "service"},
    "aws kms":          {"title": "AWS KMS",          "type": "service"},
    "aws cloudtrail":   {"title": "AWS CloudTrail",   "type": "service"},
    "aws config":       {"title": "AWS Config",       "type": "service"},
    "aws cloudwatch":   {"title": "AWS CloudWatch",   "type": "service"},
    "vpc flow logs":    {"title": "VPC Flow Logs",    "type": "service"},
    "github":           {"title": "GitHub",           "type": "software"},
    "github actions":   {"title": "GitHub Actions",   "type": "software"},
    "codeql":           {"title": "CodeQL",           "type": "software"},
    "trivy":            {"title": "Trivy",            "type": "software"},
    "prowler":          {"title": "Prowler",          "type": "software"},
    "jenkins":          {"title": "Jenkins",          "type": "software"},
    "splunk":           {"title": "Splunk",           "type": "software"},
    "okta":             {"title": "Okta",             "type": "service"},
    "azure ad":         {"title": "Azure AD",         "type": "service"},
    "duo":              {"title": "Duo",              "type": "service"},
}

# Sort by key length descending so "github actions" matches before "github"
_SORTED_KEYS = sorted(KNOWN_COMPONENTS.keys(), key=len, reverse=True)


def extract_components_from_text(text: str) -> list:
    """
    Scan text for mentions of known tools/services.
    Returns list of component keys found (e.g., ["aws iam", "github"]).
    Name recognition only — no control mapping.
    """
    if not text:
        return []
    lower = text.lower()
    found = []
    for key in _SORTED_KEYS:
        if key in lower:
            found.append(key)
            # Remove matched text to avoid "github actions" also matching "github"
            lower = lower.replace(key, "")
    return found


# ── Screenshot capture ────────────────────────────────────────────────────────

def capture_screenshot(text: str, output_path: str) -> str:
    """
    Render CLI text output to a PNG image using Pillow.
    Returns the path to the saved PNG.
    """
    from PIL import Image, ImageDraw, ImageFont

    lines = text.split("\n")
    try:
        font = ImageFont.truetype("Courier", 14)
    except (OSError, IOError):
        try:
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 14)
        except (OSError, IOError):
            font = ImageFont.load_default()

    char_width = 8
    line_height = 18
    padding = 20
    max_line_len = max((len(line) for line in lines), default=40)
    img_width = max(max_line_len * char_width + padding * 2, 400)
    img_height = len(lines) * line_height + padding * 2

    img = Image.new("RGB", (img_width, img_height), color=(30, 30, 30))
    draw = ImageDraw.Draw(img)

    y = padding
    for line in lines:
        draw.text((padding, y), line, fill=(220, 220, 220), font=font)
        y += line_height

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    img.save(output_path)
    return output_path


# ── OSCAL helpers ─────────────────────────────────────────────────────────────

def load_oscal(path: str) -> dict:
    """Load an OSCAL JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_oscal(data: dict, path: str):
    """Write an OSCAL JSON file with pretty formatting."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"    Written: {path}")


def make_observation(obs_uuid_name: str, title: str, description: str,
                     source: str, control_id: str, status: str,
                     screenshot_path: str = None) -> dict:
    """Build an OSCAL observation entry for assessment-results."""
    obs = {
        "uuid": stable_uuid(obs_uuid_name),
        "title": title,
        "description": description,
        "methods": ["TEST"],
        "subjects": [
            {
                "subject-uuid": stable_uuid(f"component:{source}"),
                "type": "component",
            }
        ],
        "props": [
            {"name": "source", "value": source},
            {"name": "control-id", "value": control_id},
            {"name": "status", "value": status},
        ],
        "collected": now_iso(),
    }
    if screenshot_path:
        obs["props"].append({"name": "evidence-screenshot", "value": screenshot_path})
    return obs


def make_finding(finding_uuid_name: str, title: str, description: str,
                 control_id: str, status: str, source: str,
                 observation_uuids: list = None) -> dict:
    """Build an OSCAL finding entry for assessment-results."""
    finding = {
        "uuid": stable_uuid(finding_uuid_name),
        "title": title,
        "description": description,
        "target": {
            "type": "objective-id",
            "target-id": control_id,
            "status": {"state": status},
        },
        "props": [
            {"name": "source", "value": source},
        ],
    }
    if observation_uuids:
        finding["related-observations"] = [
            {"observation-uuid": uid} for uid in observation_uuids
        ]
    return finding


def make_poam_item(item_uuid_name: str, title: str, description: str,
                   control_id: str, source: str) -> dict:
    """Build a POA&M item."""
    return {
        "uuid": stable_uuid(item_uuid_name),
        "title": title,
        "description": description,
        "props": [
            {"name": "control-id", "value": control_id},
            {"name": "source", "value": source},
            {"name": "status", "value": "open"},
            {"name": "created", "value": now_iso()},
        ],
    }
```

- [ ] **Step 2: Verify it loads**

Run: `cd "/Users/jleepe/CascadeProjects/repo/GRC Club Demo" && python3 -c "from scripts.pipeline_utils import stable_uuid, KNOWN_COMPONENTS, extract_components_from_text; print(f'Components: {len(KNOWN_COMPONENTS)}'); print(extract_components_from_text('We use AWS IAM and GitHub for access control'))"`

Expected: `Components: 17` and `['aws iam', 'github']`

- [ ] **Step 3: Commit**

```bash
git add scripts/pipeline_utils.py
git commit -m "refactor: replace TOOL_REGISTRY with KNOWN_COMPONENTS in pipeline_utils

KNOWN_COMPONENTS is name recognition only — no control mapping,
no evidence method inference. extract_components_from_text() scans
narratives for tool mentions. Discovery builds the real inventory."
```

---

### Task 3: Refactor excel_to_oscal.py — remove registry, add keyword extraction

**Files:**
- Modify: `scripts/excel_to_oscal.py`

This is the largest change. Remove TOOL_REGISTRY, get_tools_for_control, infer_evidence_method, build_by_components, and build_component_definitions. Replace with keyword extraction from narratives.

- [ ] **Step 1: Rewrite excel_to_oscal.py**

The full refactored file. Key changes marked with comments:

```python
"""
excel_to_oscal.py — Workshop Edition (Discovery-Driven)

Converts a FedRAMP Moderate template SSP (Excel) into OSCAL JSON.
Reads what the SSP says — extracts components mentioned in narratives
via keyword matching. Does NOT assume what tools should exist or
what controls they map to. Discovery fills that in.

USAGE:
  python excel_to_oscal.py --input templates/fedramp-moderate-template-ssp.xlsx --output oscal/
  python excel_to_oscal.py --help

MODELS PRODUCED:
  Model 4 (SSP):          oscal/ssp.json — the claim
  Model 6 (AR):           oscal/assessment-results.json — skeleton
  Model 7 (POA&M):        oscal/poam.json — skeleton
"""

import json
import os
import sys
import re
import uuid
import argparse
from datetime import datetime, timezone
from pathlib import Path

try:
    import openpyxl
except ImportError:
    print("ERROR: openpyxl not installed.")
    print("Run: pip install openpyxl")
    sys.exit(1)

# Import shared utilities
sys.path.insert(0, os.path.dirname(__file__))
from pipeline_utils import (
    stable_uuid, OSCAL_NAMESPACE, KNOWN_COMPONENTS, extract_components_from_text,
)


# ── Excel configuration ───────────────────────────────────────────────────────

SHEET_NAME = "FedRAMP Moderate Baseline"
HEADER_ROW = 1
DATA_START_ROW = 2

COLUMNS = {
    "number":          1,
    "family":          2,
    "control_id":      3,
    "control_name":    4,
    "control_text":    5,
    "related":         6,
    "status":          7,
    "evidence_method": 8,
    "implementation":  9,
}

VALID_STATUSES = {
    "implemented":    "implemented",
    "inherited":      "inherited",
    "planned":        "planned",
    "not applicable": "not-applicable",
    "not-applicable": "not-applicable",
    "n/a":            "not-applicable",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def normalize_control_id(raw_id: str) -> str:
    if not raw_id:
        return None
    s = str(raw_id).strip().lower()
    s = re.sub(r'-0*(\d)', r'-\1', s)
    s = re.sub(r'\(0*(\d+)\)', r'(\1)', s)
    return s


def normalize_status(raw_status: str) -> str:
    if not raw_status:
        return "not-implemented"
    key = str(raw_status).strip().lower()
    return VALID_STATUSES.get(key, "not-implemented")


def get_cell(sheet, row: int, col: int):
    val = sheet.cell(row=row, column=col).value
    if val is None:
        return None
    cleaned = str(val).strip()
    return cleaned if cleaned else None


def is_missing_or_stale(text, status):
    if not text:
        return True, "missing"
    if status == "implemented" and len(text) < 50:
        return True, "stale"
    return False, None


def build_by_components_from_narrative(narrative: str) -> tuple:
    """
    Scan the narrative for mentions of known tools/services.
    Returns (by_components list, component_keys found).
    No control mapping — just name recognition.
    """
    component_keys = extract_components_from_text(narrative)
    by_components = []
    for key in component_keys:
        comp = KNOWN_COMPONENTS[key]
        by_components.append({
            "component-uuid": stable_uuid(f"component:{key}"),
            "description": comp["title"],
            "implementation-status": {
                "state": "claimed",
                "remarks": "referenced in SSP narrative"
            },
            "props": [
                {"name": "component-key", "value": key},
                {"name": "origin",        "value": "ssp-narrative"},
            ]
        })
    return by_components, component_keys


# ── Build component definitions ──────────────────────────────────────────────

def build_component_definitions(discovered_keys: set):
    """Build components section from what was actually found in narratives."""
    components = [
        {
            "uuid": stable_uuid("component:this-system"),
            "type": "this-system",
            "title": "Workshop Demo System",
            "description": (
                "A demo system built during the GRC Engineering Club "
                "OSCAL builder session."
            ),
            "status": {"state": "operational"}
        }
    ]
    for key in sorted(discovered_keys):
        comp = KNOWN_COMPONENTS[key]
        components.append({
            "uuid": stable_uuid(f"component:{key}"),
            "type": comp["type"],
            "title": comp["title"],
            "props": [
                {"name": "component-key", "value": key},
                {"name": "origin",        "value": "ssp-narrative"},
            ],
            "status": {"state": "operational"}
        })
    return components


# ── Build assessment results skeleton ────────────────────────────────────────

def build_assessment_results_skeleton(ssp_uuid: str):
    ar_uuid = stable_uuid("assessment-results:workshop")
    return {
        "assessment-results": {
            "uuid": ar_uuid,
            "metadata": {
                "title": "Workshop Demo — Assessment Results",
                "last-modified": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "version": "1.0.0",
                "oscal-version": "1.1.2",
            },
            "import-ap": {
                "href": "#",
                "remarks": "Assessment plan is automated — the pipeline scripts define what's checked and how."
            },
            "results": [
                {
                    "uuid": stable_uuid("result:workshop-run"),
                    "title": "Workshop Pipeline Run",
                    "description": "Evidence collected against FedRAMP Moderate baseline.",
                    "start": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "reviewed-controls": {
                        "control-selections": [
                            {"include-all": {}}
                        ]
                    },
                    "observations": [],
                    "findings": [],
                }
            ]
        }
    }


# ── Build POA&M skeleton ─────────────────────────────────────────────────────

def build_poam_skeleton(ssp_uuid: str):
    return {
        "plan-of-action-and-milestones": {
            "uuid": stable_uuid("poam:workshop"),
            "metadata": {
                "title": "Workshop Demo — Plan of Action and Milestones",
                "last-modified": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "version": "1.0.0",
                "oscal-version": "1.1.2",
            },
            "import-ssp": {
                "href": "ssp.json"
            },
            "poam-items": []
        }
    }


# ── Main converter ────────────────────────────────────────────────────────────

def convert_excel_to_oscal(input_path: str, output_dir: str):
    print(f"\n{'='*62}")
    print(f"  FedRAMP Moderate SSP → OSCAL Converter")
    print(f"  Discovery-Driven — SSP as claim, no assumptions")
    print(f"{'='*62}")
    print(f"  Input:      {input_path}")
    print(f"  Output dir: {output_dir}")
    print(f"{'='*62}\n")

    print(f"  Opening Excel SSP...")
    try:
        wb = openpyxl.load_workbook(input_path, data_only=True)
    except Exception as e:
        print(f"  ERROR: Could not open Excel file: {e}")
        return False

    if SHEET_NAME not in wb.sheetnames:
        print(f"  ERROR: Sheet '{SHEET_NAME}' not found.")
        print(f"  Available sheets: {wb.sheetnames}")
        return False

    ws = wb[SHEET_NAME]
    print(f"  Found sheet: {SHEET_NAME}")
    print(f"  Extracting controls and scanning narratives for components...\n")

    implemented_requirements = []
    all_component_keys = set()
    stats = {
        "total": 0, "implemented": 0, "inherited": 0, "planned": 0,
        "not_applicable": 0, "has_narrative": 0, "missing_narrative": 0,
        "controls_with_components": 0, "controls_without_components": 0,
    }

    for row_num in range(DATA_START_ROW, ws.max_row + 1):
        row_data = {key: get_cell(ws, row_num, col) for key, col in COLUMNS.items()}

        if not row_data["control_id"]:
            continue

        stats["total"] += 1
        control_id = normalize_control_id(row_data["control_id"])
        if not control_id:
            continue

        status = normalize_status(row_data["status"])
        family = control_id.split("-")[0] if "-" in control_id else ""
        ssp_text = row_data["implementation"]
        needs_review, review_reason = is_missing_or_stale(ssp_text, status)

        # Stats
        stat_map = {"implemented": "implemented", "inherited": "inherited",
                    "planned": "planned", "not-applicable": "not_applicable"}
        if status in stat_map:
            stats[stat_map[status]] += 1
        if ssp_text and not needs_review:
            stats["has_narrative"] += 1
        else:
            stats["missing_narrative"] += 1

        # Extract components from narrative
        by_components, component_keys = build_by_components_from_narrative(ssp_text or "")
        all_component_keys.update(component_keys)

        if component_keys:
            stats["controls_with_components"] += 1
        else:
            stats["controls_without_components"] += 1

        # Control-level props
        props = [
            {"name": "control-origination", "value": status},
            {"name": "control-family",       "value": family.upper()},
            {"name": "last-reconciled",      "value": "never"},
        ]

        if needs_review:
            props.append({"name": "review-flag", "value": review_reason})

        if ssp_text:
            props.append({"name": "baseline-narrative", "value": ssp_text})

        # Build the implemented-requirement
        impl_req = {
            "uuid": stable_uuid(f"impl-req:{control_id}"),
            "control-id": control_id,
            "props": props,
            "statements": [
                {
                    "statement-id": f"{control_id}_smt",
                    "uuid": stable_uuid(f"stmt:{control_id}"),
                    "description": ssp_text or "Implementation statement not yet documented.",
                    "by-components": by_components,
                }
            ]
        }
        implemented_requirements.append(impl_req)

        comp_display = ", ".join(component_keys) if component_keys else "(none)"
        print(f"  {control_id.upper():10s} {status:18s} components: {comp_display:30s} "
              f"{'✓' if ssp_text else '✗'} narrative")

    # ── Build the SSP ────────────────────────────────────────────────────────

    ssp_uuid = stable_uuid("ssp:workshop-demo")

    oscal_ssp = {
        "system-security-plan": {
            "uuid": ssp_uuid,
            "metadata": {
                "title": "Workshop Demo — System Security Plan",
                "last-modified": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "version": "1.0.0",
                "oscal-version": "1.1.2",
                "remarks": (
                    "Generated by GRC Engineering Club workshop converter. "
                    "FedRAMP Moderate baseline. Components extracted from SSP "
                    "narratives — discovery fills in the real inventory."
                ),
            },
            "import-profile": {
                "href": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json",
                "remarks": "FedRAMP Moderate baseline from NIST OSCAL content repository"
            },
            "system-characteristics": {
                "system-ids": [
                    {"id": "WORKSHOP-DEMO-001"}
                ],
                "system-name": "GRC Engineering Club Workshop Demo",
                "description": (
                    "A demonstration system built during the live builder session. "
                    "Components are extracted from SSP narratives. Discovery identifies "
                    "the actual environment inventory."
                ),
                "security-sensitivity-level": "moderate",
                "system-information": {
                    "information-types": [
                        {
                            "uuid": stable_uuid("info-type:demo"),
                            "title": "Workshop Demonstration Data",
                            "description": "Non-sensitive demonstration data for OSCAL pipeline training.",
                            "categorizations": [
                                {"system": "https://doi.org/10.6028/NIST.SP.800-60v2r1"}
                            ],
                            "confidentiality-impact": {"base": "fips-199-moderate"},
                            "integrity-impact":      {"base": "fips-199-moderate"},
                            "availability-impact":   {"base": "fips-199-moderate"},
                        }
                    ]
                },
                "security-impact-level": {
                    "security-objective-confidentiality": "fips-199-moderate",
                    "security-objective-integrity":       "fips-199-moderate",
                    "security-objective-availability":    "fips-199-moderate",
                },
                "status": {"state": "operational"},
                "authorization-boundary": {
                    "description": "AWS account, GitHub repositories, and associated security tooling."
                },
            },
            "system-implementation": {
                "users": [
                    {
                        "uuid": stable_uuid("user:workshop-participant"),
                        "title": "Workshop Participant",
                        "role-ids": ["system-owner"],
                        "description": "GRC Engineering Club member building the demo pipeline."
                    }
                ],
                "components": build_component_definitions(all_component_keys),
            },
            "control-implementation": {
                "description": (
                    "FedRAMP Moderate baseline controls with implementation narratives "
                    "as documented claims. Components extracted from narratives via "
                    "keyword matching. Discovery adds the real environment inventory."
                ),
                "implemented-requirements": implemented_requirements,
            }
        }
    }

    # ── Write all three OSCAL files ──────────────────────────────────────────

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    ssp_file = output_path / "ssp.json"
    with open(ssp_file, "w", encoding="utf-8") as f:
        json.dump(oscal_ssp, f, indent=2, ensure_ascii=False)

    ar = build_assessment_results_skeleton(ssp_uuid)
    ar_file = output_path / "assessment-results.json"
    with open(ar_file, "w", encoding="utf-8") as f:
        json.dump(ar, f, indent=2, ensure_ascii=False)

    poam = build_poam_skeleton(ssp_uuid)
    poam_file = output_path / "poam.json"
    with open(poam_file, "w", encoding="utf-8") as f:
        json.dump(poam, f, indent=2, ensure_ascii=False)

    # ── Summary ──────────────────────────────────────────────────────────────

    print(f"\n{'='*62}")
    print(f"  CONVERSION COMPLETE")
    print(f"{'='*62}")
    print(f"  OSCAL SSP:                {ssp_file}")
    print(f"  Assessment Results:       {ar_file}")
    print(f"  POA&M:                    {poam_file}")
    print(f"{'─'*62}")
    print(f"  Total controls:           {stats['total']}")
    print(f"  Implemented:              {stats['implemented']}")
    print(f"  Inherited:                {stats.get('inherited', 0)}")
    print(f"  Narratives present:       {stats['has_narrative']}")
    print(f"  Missing narratives:       {stats['missing_narrative']}")
    print(f"{'─'*62}")
    print(f"  Components from SSP:      {len(all_component_keys)}")
    if all_component_keys:
        print(f"    {', '.join(KNOWN_COMPONENTS[k]['title'] for k in sorted(all_component_keys))}")
    print(f"  Controls with components: {stats['controls_with_components']}")
    print(f"  Controls without:         {stats['controls_without_components']}")
    print(f"{'─'*62}")
    print(f"  UUID strategy:            v5 deterministic (stable diffs)")
    print(f"  Architecture:             SSP = claim | Discovery = truth | AR = evidence")
    print(f"{'='*62}")
    print(f"\n  Next: Run discovery to find what's actually in your environment")
    print(f"  python3 scripts/discover.py --ssp oscal/ssp.json --output oscal/inventory.json")
    print(f"{'='*62}\n")

    return True


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Convert FedRAMP Moderate template SSP (Excel) to OSCAL JSON"
    )
    parser.add_argument(
        "--input", "-i",
        default="Templates/fedramp-moderate-template-ssp.xlsx",
        help="Path to template SSP Excel file"
    )
    parser.add_argument(
        "--output", "-o",
        default="oscal",
        help="Output directory for OSCAL JSON files (default: oscal/)"
    )
    args = parser.parse_args()

    success = convert_excel_to_oscal(args.input, args.output)
    sys.exit(0 if success else 1)
```

- [ ] **Step 2: Test the refactored converter**

Run: `cd "/Users/jleepe/CascadeProjects/repo/GRC Club Demo" && python3 scripts/excel_to_oscal.py --input Templates/fedramp-moderate-template-ssp.xlsx --output oscal`

Expected: 57 controls. Controls with updated narratives show extracted components. Others show "(none)". No TOOL_REGISTRY references.

- [ ] **Step 3: Verify SSP JSON structure**

Run: `python3 -c "import json; ssp=json.load(open('oscal/ssp.json')); comps=ssp['system-security-plan']['system-implementation']['components']; print(f'Components: {len(comps)}'); [print(f'  {c[\"title\"]}') for c in comps]"`

Expected: Only "this-system" plus components extracted from narratives (AWS IAM, AWS CloudTrail, GitHub, Prowler, Trivy, AWS S3, AWS KMS, AWS CloudWatch, VPC Flow Logs — depending on template updates).

- [ ] **Step 4: Commit**

```bash
git add scripts/excel_to_oscal.py
git commit -m "refactor: remove TOOL_REGISTRY from Excel converter

Converter now extracts components from SSP narratives via keyword
matching. No predefined control mappings. No evidence method
inference. Components tagged with origin: ssp-narrative.
Discovery fills in the real environment inventory."
```

---

### Task 4: Refactor docx_to_oscal.py — same changes as Excel converter

**Files:**
- Modify: `scripts/docx_to_oscal.py`

Apply the same refactor pattern as Task 3: remove TOOL_REGISTRY, import from pipeline_utils, use extract_components_from_text for narratives, build components from what's found.

- [ ] **Step 1: Update docx_to_oscal.py**

The changes mirror the Excel converter:
1. Remove the `TOOL_REGISTRY` dict (lines 58-139)
2. Remove `get_tools_for_control()` and `infer_evidence_method()` functions
3. Remove `build_by_components()` that references TOOL_REGISTRY
4. Add `sys.path.insert(0, os.path.dirname(__file__))` and `from pipeline_utils import stable_uuid, OSCAL_NAMESPACE, KNOWN_COMPONENTS, extract_components_from_text`
5. Remove the local `stable_uuid` and `OSCAL_NAMESPACE` definitions (now imported)
6. Replace `build_by_components(control_id, covering_tools)` calls with `build_by_components_from_narrative(narrative_text)` using the same function from Task 3
7. Replace `build_component_definitions()` with the version from Task 3 that takes `discovered_keys`
8. Update summary output to show extracted components instead of tool registry stats
9. Update `build_assessment_results_skeleton` import-ap remarks to match Task 3
10. Remove evidence method inference — no `evidence_method` prop on controls

- [ ] **Step 2: Test**

Run: `python3 scripts/docx_to_oscal.py --input Templates/cui-ssp-template-final.docx --output /tmp/test-docx-refactor`

Expected: Converts successfully, shows extracted components from narratives.

- [ ] **Step 3: Commit**

```bash
git add scripts/docx_to_oscal.py
git commit -m "refactor: remove TOOL_REGISTRY from Word converter

Same changes as Excel converter — keyword extraction from
narratives, no predefined control mappings."
```

---

### Task 5: Refactor discover.py — real drift detection

**Files:**
- Modify: `scripts/discover.py`

- [ ] **Step 1: Update drift detection to compare SSP-claimed components against discovered resources**

Replace the `extract_ssp_components` and `detect_drift` functions:

```python
def extract_ssp_components(ssp: dict) -> dict:
    """Extract components declared in the SSP, grouped by origin."""
    components = {}
    sys_impl = ssp.get("system-security-plan", {}).get("system-implementation", {})
    for comp in sys_impl.get("components", []):
        if comp.get("type") == "this-system":
            continue
        title = comp.get("title", "")
        origin = "unknown"
        for p in comp.get("props", []):
            if p["name"] == "origin":
                origin = p["value"]
            if p["name"] == "component-key":
                key = p["value"]
        components[title.lower()] = {
            "title": title,
            "origin": origin,
            "uuid": comp.get("uuid", ""),
        }
    return components


def detect_drift(discovered: list, ssp_components: dict) -> dict:
    """
    Compare discovered resources against SSP-declared components.
    Real drift detection:
      - documented: in SSP AND in environment
      - undocumented: in environment but NOT in SSP
      - missing: in SSP but NOT in environment
    """
    # Map discovered resources to service categories
    discovered_services = set()
    for r in discovered:
        rtype = r.get("type", "")
        if "IAM" in rtype:
            discovered_services.add("aws iam")
        elif "S3" in rtype:
            discovered_services.add("aws s3")
        elif "CloudTrail" in rtype:
            discovered_services.add("aws cloudtrail")
        elif "Config" in rtype:
            discovered_services.add("aws config")
        elif "KMS" in rtype or "Key" in rtype:
            discovered_services.add("aws kms")
        elif "SecurityGroup" in rtype:
            discovered_services.add("aws security groups")
        elif "VPC" in rtype:
            discovered_services.add("aws vpc")
        elif "EC2" in rtype:
            discovered_services.add("aws ec2")
        elif "Repository" in rtype:
            discovered_services.add("github")
        elif "ActionsWorkflow" in rtype:
            discovered_services.add("github actions")
        elif "BranchProtection" in rtype:
            discovered_services.add("github")

    ssp_titles = {t for t in ssp_components.keys()}

    documented = []
    undocumented = []
    missing = []

    for svc in sorted(discovered_services):
        if svc in ssp_titles:
            documented.append(svc)
        else:
            undocumented.append(svc)

    for title in sorted(ssp_titles):
        if title not in discovered_services:
            missing.append(title)

    return {
        "total_discovered": len(discovered),
        "discovered_services": sorted(discovered_services),
        "ssp_components": len(ssp_components),
        "documented": documented,
        "undocumented": undocumented,
        "missing": missing,
    }
```

- [ ] **Step 2: Update the main() summary output to show documented/undocumented/missing**

Replace the summary section in `main()`:

```python
    # Summary
    print(f"\n{'='*62}")
    print(f"  DISCOVERY COMPLETE")
    print(f"{'='*62}")
    print(f"  Resources discovered:  {len(all_resources)}")
    print(f"    AWS:                 {len(aws_resources)}")
    print(f"    GitHub:              {len(github_resources)}")
    print(f"  SSP components:        {len(ssp_components)}")
    print(f"{'─'*62}")
    print(f"  DRIFT DETECTION")
    print(f"{'─'*62}")
    print(f"  Documented (SSP + env):    {len(drift['documented'])}")
    for s in drift["documented"]:
        print(f"    ✓ {s}")
    print(f"  Undocumented (env only):   {len(drift['undocumented'])}")
    for s in drift["undocumented"]:
        print(f"    ✗ {s}")
    print(f"  Missing (SSP only):        {len(drift['missing'])}")
    for s in drift["missing"]:
        print(f"    ? {s}")
    print(f"\n  Output: {args.output}")
    print(f"{'='*62}\n")
```

- [ ] **Step 3: Test discovery with refactored converter output**

Run: `cd "/Users/jleepe/CascadeProjects/repo/GRC Club Demo" && export $(cat .env | grep -v '^#' | xargs) && python3 scripts/discover.py --ssp oscal/ssp.json --output oscal/inventory.json --github-repo oscal-pipeline-workshop`

Expected: Drift detection shows documented components (things SSP mentions that exist), undocumented (things in AWS/GitHub the SSP doesn't mention like KMS, security groups, VPC), and missing (things SSP claims that aren't found).

- [ ] **Step 4: Commit**

```bash
git add scripts/discover.py
git commit -m "refactor: real drift detection in discovery

Compares SSP-claimed components against discovered resources.
Shows documented (SSP + env), undocumented (env only), and
missing (SSP only) categories."
```

---

### Task 6: Refactor assess.py — remove registry references, evidence method from results

**Files:**
- Modify: `scripts/assess.py`

- [ ] **Step 1: Remove TOOL_REGISTRY import and references**

At the top of assess.py, change the import from pipeline_utils:

```python
from pipeline_utils import (
    stable_uuid, now_iso, now_filesafe, load_oscal, save_oscal,
    capture_screenshot, make_observation, make_finding,
)
```

Remove `TOOL_REGISTRY` from the import — it no longer exists.

- [ ] **Step 2: Add evidence method determination at the end of main()**

After all findings are collected and before writing the output, add this block after the screenshot/findings loop:

```python
    # Determine evidence method per control from actual results
    control_sources = {}
    for f in all_findings:
        ctrl = f["control"]
        src = f["source"]
        if ctrl not in control_sources:
            control_sources[ctrl] = set()
        control_sources[ctrl].add(src)

    # Add evidence-method to each finding based on source count
    for finding in result["findings"]:
        ctrl = finding.get("target", {}).get("target-id", "")
        sources = control_sources.get(ctrl, set())
        if len(sources) >= 2:
            method = "automated"
        elif len(sources) == 1:
            method = "hybrid"
        else:
            method = "manual"
        finding["props"].append({"name": "evidence-method", "value": method})
```

- [ ] **Step 3: Test**

Run: `python3 scripts/assess.py --help`

Expected: No import errors. Help text displays.

- [ ] **Step 4: Commit**

```bash
git add scripts/assess.py
git commit -m "refactor: remove TOOL_REGISTRY from assessment, determine evidence method from results

Evidence method now based on actual source count per control:
2+ sources = automated, 1 source = hybrid, 0 = manual."
```

---

### Task 7: Refactor reconcile.py — flag undocumented resources

**Files:**
- Modify: `scripts/reconcile.py`

- [ ] **Step 1: Add undocumented resource handling**

In the `reconcile()` function, after processing SSP claims, add:

```python
    # Flag undocumented resources from inventory
    if inventory:
        drift = inventory.get("inventory", {}).get("drift-summary", {})
        for item in drift.get("undocumented", []):
            name = item if isinstance(item, str) else item.get("name", str(item))
            results[f"undocumented:{name}"] = {
                "claim": "not-documented",
                "verdict": "undocumented",
                "evidence_count": 0,
                "failures": [],
                "passes": [],
                "sources": ["discovery"],
            }
```

- [ ] **Step 2: Update build_poam to handle undocumented verdict**

In `build_poam()`, add after the "unverified" block:

```python
        elif result["verdict"] == "undocumented":
            control_display = control_id.replace("undocumented:", "")
            poam_items.append(make_poam_item(
                f"poam:{control_id}:undocumented",
                f"Undocumented resource: {control_display}",
                (f"Resource '{control_display}' exists in the environment but is not "
                 f"documented in the SSP. It may affect security controls."),
                control_id,
                "discovery",
            ))
```

- [ ] **Step 3: Test**

Run: `python3 scripts/reconcile.py --help`

Expected: No import errors.

- [ ] **Step 4: Commit**

```bash
git add scripts/reconcile.py
git commit -m "refactor: flag undocumented resources as POA&M items

Resources found by discovery but not in SSP are now
tracked as POA&M items with source: discovery."
```

---

### Task 8: Update discover.py inventory to include drift in output

**Files:**
- Modify: `scripts/discover.py`

- [ ] **Step 1: Update build_inventory to store undocumented items as strings**

In the `build_inventory` function, ensure the drift-summary undocumented list stores service names as strings (not dicts) so reconcile.py can read them:

```python
            "drift-summary": {
                "total-discovered": drift["total_discovered"],
                "ssp-components": drift["ssp_components"],
                "documented": drift["documented"],
                "undocumented": drift["undocumented"],
                "missing": drift["missing"],
            },
```

- [ ] **Step 2: Commit**

```bash
git add scripts/discover.py
git commit -m "fix: store drift categories as string lists in inventory output"
```

---

### Task 9: Smoke test the full refactored pipeline

- [ ] **Step 1: Run converter**

```bash
cd "/Users/jleepe/CascadeProjects/repo/GRC Club Demo"
export $(cat .env | grep -v '^#' | xargs)
python3 scripts/excel_to_oscal.py --input Templates/fedramp-moderate-template-ssp.xlsx --output oscal
```

Expected: 57 controls. Components extracted from updated narratives. No TOOL_REGISTRY.

- [ ] **Step 2: Run discovery**

```bash
python3 scripts/discover.py --ssp oscal/ssp.json --output oscal/inventory.json --github-repo oscal-pipeline-workshop
```

Expected: Drift detection shows documented/undocumented/missing.

- [ ] **Step 3: Run assessment**

```bash
python3 scripts/assess.py --ssp oscal/ssp.json --github-repo oscal-pipeline-workshop --skip-prowler --skip-trivy --skip-nvd
```

Expected: Findings with evidence method determined from results.

- [ ] **Step 4: Run reconcile**

```bash
python3 scripts/reconcile.py --ssp oscal/ssp.json --results oscal/assessment-results.json --inventory oscal/inventory.json --output oscal/poam.json
```

Expected: POA&M includes undocumented resources from drift detection.

- [ ] **Step 5: Run enforce**

```bash
python3 scripts/enforce.py --results oscal/assessment-results.json --poam oscal/poam.json --no-issue
```

Expected: FAIL with findings including undocumented resources.

- [ ] **Step 6: Final commit and push**

```bash
git add -A
git status
git commit -m "chore: smoke test passing on refactored pipeline"
git push origin main
```
