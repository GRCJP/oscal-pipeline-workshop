"""
excel_to_oscal.py — Workshop Edition

Converts a FedRAMP Moderate template SSP (Excel) into OSCAL JSON.
Produces Model 5 (System Security Plan) with by-component slots
for each tool in the TOOL_REGISTRY.

ARCHITECTURE:
  The OSCAL skeleton is master. The SSP carries the CLAIM.
  Evidence goes into assessment-results.json (separate artifact).
  Ingest scripts write there — not here.

TOOL_REGISTRY:
  6 free tools that members set up in the pre-reqs:
  - aws_iam       → Identity (AC, IA)
  - aws_s3        → Encryption & storage (SC, CP)
  - github        → Source control (CM, SA)
  - github_actions → CI/CD pipeline (SA, CM, SI)
  - jenkins       → CI/CD pipeline, second witness (SA, CM)
  - nvd           → Vulnerability data (RA, SI)

USAGE:
  python excel_to_oscal.py --input templates/fedramp-moderate-template-ssp.xlsx --output oscal/ssp.json
  python excel_to_oscal.py --help

MODELS PRODUCED:
  Model 5: oscal/ssp.json              — System Security Plan (the claim)
  Model 7: oscal/assessment-results.json — skeleton (ingest scripts populate)
  Model 8: oscal/poam.json             — skeleton (reconciler populates)
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


# ── UUID v5 deterministic identifiers ─────────────────────────────────────────
# Same namespace across ALL scripts. Produces stable UUIDs for clean Git diffs.

OSCAL_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

def stable_uuid(name: str) -> str:
    return str(uuid.uuid5(OSCAL_NAMESPACE, name))


# ── Tool Registry ─────────────────────────────────────────────────────────────
# 6 free tools. Each gets a by-component slot on every control.
# Ingest scripts decide which slots to populate based on actual API data.

TOOL_REGISTRY = {
    "aws_iam": {
        "title": "AWS IAM",
        "type": "service",
        "families": ["ac", "ia"],
        "controls": ["ac-2", "ac-2(1)", "ac-3", "ac-5", "ac-6", "ac-6(1)", "ac-7", "ia-2", "ia-2(1)", "ia-4", "ia-5", "ia-5(1)"],
        "evidence_type": "Cloud Identity & Access",
        "what_it_proves": "IAM users, MFA status, access key age, permission boundaries, least privilege, account lockout policies",
    },
    "aws_s3": {
        "title": "AWS S3 & KMS",
        "type": "service",
        "families": ["sc", "cp", "au"],
        "controls": ["sc-28", "sc-7", "sc-8", "sc-12", "sc-13", "cp-9", "au-9"],
        "evidence_type": "Data Encryption, Storage & Backup",
        "what_it_proves": "Bucket encryption, public access blocks, versioning, backup config, key management, log protection",
    },
    "aws_cloudtrail": {
        "title": "AWS CloudTrail",
        "type": "service",
        "families": ["au"],
        "controls": ["au-2", "au-3", "au-12"],
        "evidence_type": "Audit Logging",
        "what_it_proves": "Trail configuration, event types logged, log delivery, multi-region coverage",
    },
    "github": {
        "title": "GitHub",
        "type": "software",
        "families": ["cm", "sa"],
        "controls": ["cm-2", "cm-3", "cm-5", "cm-7", "cm-8", "sa-10"],
        "evidence_type": "Source Control & Change Management",
        "what_it_proves": "Branch protection, PR approvals, code review, commit audit trail, baseline config in repos",
    },
    "github_actions": {
        "title": "GitHub Actions",
        "type": "software",
        "families": ["sa", "cm", "si"],
        "controls": ["sa-10", "sa-11", "cm-3", "si-2"],
        "evidence_type": "CI/CD Pipeline Security",
        "what_it_proves": "Security scan gates, build pass/fail history, deployment approvals, flaw remediation",
    },
    "jenkins": {
        "title": "Jenkins",
        "type": "software",
        "families": ["sa", "cm"],
        "controls": ["sa-10", "sa-11", "cm-3"],
        "evidence_type": "CI/CD Pipeline Security",
        "what_it_proves": "Pipeline build history, security gate enforcement, plugin vulnerability status",
    },
    "nvd": {
        "title": "NIST NVD / OSV.dev",
        "type": "service",
        "families": ["ra", "si"],
        "controls": ["ra-5", "si-2"],
        "evidence_type": "Vulnerability Intelligence",
        "what_it_proves": "Known CVEs against dependencies, severity distribution, patch availability",
    },
    "prowler": {
        "title": "Prowler (Open Source CSPM)",
        "type": "software",
        "families": ["ac", "au", "cm", "ia", "ra", "sc", "si"],
        "controls": ["ac-2", "ac-3", "ac-6", "ac-7", "au-2", "au-9", "cm-6", "cm-7", "ia-2", "ia-5", "ra-5", "sc-7", "sc-28", "si-4"],
        "evidence_type": "Cloud Security Posture Management",
        "what_it_proves": "CIS benchmark compliance, FedRAMP check results, misconfiguration findings across all AWS services",
    },
}


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


def get_tools_for_control(control_id: str) -> list:
    """Return tool keys whose control list includes this control."""
    tools = []
    for key, tool in TOOL_REGISTRY.items():
        if control_id in tool["controls"]:
            tools.append(key)
    return tools


def is_missing_or_stale(text, status):
    if not text:
        return True, "missing"
    if status == "implemented" and len(text) < 50:
        return True, "stale"
    return False, None


def build_by_components(control_id: str, tool_keys: list) -> list:
    """
    Build the by-component slots for a control.
    Every tool that covers this control gets an open slot.
    Ingest scripts populate them later via assessment-results.json.
    """
    components = []
    for tool_key in tool_keys:
        tool = TOOL_REGISTRY[tool_key]
        components.append({
            "component-uuid": stable_uuid(f"component:{tool_key}"),
            "description": "",
            "implementation-status": {
                "state": "planned",
                "remarks": "pending-ingest — no API evidence yet"
            },
            "props": [
                {"name": "tool-key",       "value": tool_key},
                {"name": "evidence-type",  "value": tool["evidence_type"]},
            ]
        })
    return components


# ── Build component definitions (Model 4) ────────────────────────────────────

def build_component_definitions():
    components = [
        {
            "uuid": stable_uuid("component:this-system"),
            "type": "this-system",
            "title": "Workshop Demo System",
            "description": (
                "A demo system built during the GRC Engineering Club "
                "OSCAL builder session. Uses AWS free tier, GitHub, "
                "Jenkins, and NIST NVD as evidence sources."
            ),
            "status": {"state": "operational"}
        }
    ]
    for tool_key, tool in TOOL_REGISTRY.items():
        components.append({
            "uuid": stable_uuid(f"component:{tool_key}"),
            "type": tool["type"],
            "title": tool["title"],
            "description": f"{tool['evidence_type']} — {tool['what_it_proves']}",
            "props": [
                {"name": "tool-key",          "value": tool_key},
                {"name": "evidence-type",      "value": tool["evidence_type"]},
                {"name": "control-families",   "value": ", ".join(tool["families"]).upper()},
            ],
            "status": {"state": "operational"}
        })
    return components


# ── Build assessment results skeleton (Model 7) ──────────────────────────────

def build_assessment_results_skeleton(ssp_uuid: str):
    """
    Creates the assessment-results.json skeleton.
    Ingest scripts write observations and findings here.
    The reconciler reads SSP (claim) + AR (evidence) and writes verdicts.
    """
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
                "remarks": "No formal assessment plan for workshop demo. Controls assessed per CONNECTOR-SPEC.md."
            },
            "results": [
                {
                    "uuid": stable_uuid("result:workshop-run"),
                    "title": "Workshop Pipeline Run",
                    "description": "Evidence collected from 6 free tools against FedRAMP Moderate baseline.",
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


# ── Build POA&M skeleton (Model 8) ───────────────────────────────────────────

def build_poam_skeleton(ssp_uuid: str):
    """
    Creates the poam.json skeleton.
    The reconciler populates this with CONTRADICTED and PARTIAL controls.
    """
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
    print(f"  Workshop Edition — 8 OSCAL Models")
    print(f"  Skeleton as master | SSP as claim | Separated AR + POA&M")
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
    print(f"  Building OSCAL skeleton — SSP as claim, open evidence slots...\n")

    implemented_requirements = []
    stats = {
        "total": 0, "implemented": 0, "inherited": 0, "planned": 0,
        "not_applicable": 0, "has_narrative": 0, "missing_narrative": 0,
        "tool_slots_created": 0,
        "automated": 0, "manual": 0, "hybrid": 0, "inherited_evidence": 0,
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
        evidence_method = (row_data.get("evidence_method") or "Manual").strip().lower()
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

        # Evidence method stats
        ev_stat_map = {"automated": "automated", "manual": "manual",
                       "hybrid": "hybrid", "inherited": "inherited_evidence"}
        if evidence_method in ev_stat_map:
            stats[ev_stat_map[evidence_method]] += 1

        # Tools that cover this control
        covering_tools = get_tools_for_control(control_id)
        by_components = build_by_components(control_id, covering_tools)
        stats["tool_slots_created"] += len(by_components)

        # Control-level props
        props = [
            {"name": "control-origination", "value": status},
            {"name": "control-family",       "value": family.upper()},
            {"name": "evidence-method",      "value": evidence_method},
            {"name": "last-reconciled",      "value": "never"},
        ]

        if needs_review:
            props.append({"name": "review-flag", "value": review_reason})

        # The baseline narrative — this is the SSP CLAIM
        # Ingest scripts never overwrite this. Evidence goes to assessment-results.json.
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

        print(f"  {control_id.upper():10s} {status:18s} {evidence_method:10s} tools: {len(covering_tools):2d}  "
              f"{'✓' if ssp_text else '✗'} narrative")

    # ── Build the SSP (Model 5) ───────────────────────────────────────────────

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
                    "FedRAMP Moderate baseline. 6 free tools as evidence sources. "
                    "SSP carries the CLAIM. Evidence goes to assessment-results.json."
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
                    "Uses AWS free tier, GitHub, Jenkins, and NIST NVD as evidence "
                    "sources to demonstrate the full OSCAL model stack."
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
                    "description": "AWS free tier account, GitHub repositories, local Jenkins instance, and NIST NVD public API."
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
                "components": build_component_definitions(),
            },
            "control-implementation": {
                "description": (
                    "FedRAMP Moderate baseline controls with implementation narratives "
                    "as documented claims. Each control has by-component slots for every "
                    "tool in the TOOL_REGISTRY. Evidence is collected in assessment-results.json."
                ),
                "implemented-requirements": implemented_requirements,
            }
        }
    }

    # ── Write all three OSCAL files ───────────────────────────────────────────

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Model 5: SSP
    ssp_file = output_path / "ssp.json"
    with open(ssp_file, "w", encoding="utf-8") as f:
        json.dump(oscal_ssp, f, indent=2, ensure_ascii=False)

    # Model 7: Assessment Results skeleton
    ar = build_assessment_results_skeleton(ssp_uuid)
    ar_file = output_path / "assessment-results.json"
    with open(ar_file, "w", encoding="utf-8") as f:
        json.dump(ar, f, indent=2, ensure_ascii=False)

    # Model 8: POA&M skeleton
    poam = build_poam_skeleton(ssp_uuid)
    poam_file = output_path / "poam.json"
    with open(poam_file, "w", encoding="utf-8") as f:
        json.dump(poam, f, indent=2, ensure_ascii=False)

    # ── Summary ───────────────────────────────────────────────────────────────

    print(f"\n{'='*62}")
    print(f"  CONVERSION COMPLETE")
    print(f"{'='*62}")
    print(f"  OSCAL Model 5 (SSP):                {ssp_file}")
    print(f"  OSCAL Model 7 (Assessment Results):  {ar_file}")
    print(f"  OSCAL Model 8 (POA&M):               {poam_file}")
    print(f"{'─'*62}")
    print(f"  Total controls:        {stats['total']}")
    print(f"  Implemented:           {stats['implemented']}")
    print(f"  Inherited:             {stats.get('inherited', 0)}")
    print(f"  Narratives present:    {stats['has_narrative']}")
    print(f"  Missing narratives:    {stats['missing_narrative']}")
    print(f"{'─'*62}")
    print(f"  Evidence methods:")
    print(f"    Automated:           {stats['automated']}  ← tools verify via API")
    print(f"    Manual:              {stats['manual']}  ← examiner attestation required")
    print(f"    Hybrid:              {stats['hybrid']}   ← tool evidence + human review")
    print(f"    Inherited:           {stats['inherited_evidence']}   ← CSP responsibility")
    print(f"{'─'*62}")
    print(f"  Tool slots created:    {stats['tool_slots_created']}")
    print(f"  Tools in registry:     {len(TOOL_REGISTRY)}")
    print(f"{'─'*62}")
    print(f"  UUID strategy:         v5 deterministic (stable diffs)")
    print(f"  Architecture:          SSP = claim | AR = evidence | POA&M = action")
    print(f"  Profile reference:     FedRAMP Moderate (NIST oscal-content)")
    print(f"{'='*62}")
    print(f"\n  OSCAL Models produced:")
    print(f"  ✓ Model 1 (Catalog):     referenced via profile → NIST 800-53 Rev 5")
    print(f"  ✓ Model 2 (Profile):     referenced → FedRAMP Moderate baseline")
    print(f"  ✓ Model 4 (Components):  {len(TOOL_REGISTRY)} tools defined in SSP")
    print(f"  ✓ Model 5 (SSP):         {stats['total']} controls with baseline narratives")
    print(f"  ✓ Model 7 (AR):          skeleton — ingest scripts populate")
    print(f"  ✓ Model 8 (POA&M):       skeleton — reconciler populates")
    print(f"\n  Models NOT produced (out of scope for workshop):")
    print(f"    Model 3 (Mapping):     cross-framework mapping (ARC-AMPE ↔ Pub 1075)")
    print(f"    Model 6 (AP):          formal assessment plan")
    print(f"\n  Next steps:")
    print(f"  1. Use your AI tool to build aws_iam_ingest.py")
    print(f"  2. Run it against your AWS account")
    print(f"  3. Run reconcile_oscal.py to compare claim vs evidence")
    print(f"  4. Generate dashboard to see findings")
    print(f"{'='*62}\n")

    return True


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Convert FedRAMP Moderate template SSP (Excel) to OSCAL JSON"
    )
    parser.add_argument(
        "--input", "-i",
        default="templates/fedramp-moderate-template-ssp.xlsx",
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
