# OSCAL Pipeline Full Flow — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the oscal-pipeline-workshop from an SSP converter into a complete 5-stage OSCAL compliance pipeline: discover, assess, reconcile, enforce, and a runner to tie it all together.

**Architecture:** Each stage is a standalone Python script that reads OSCAL JSON inputs and writes OSCAL JSON outputs. The converter (stage 1) already exists. We build stages 2-5 plus a runner. All scripts follow the same patterns as `excel_to_oscal.py`: argparse CLI, deterministic UUIDs via `stable_uuid()`, banner-style console output, and the `OSCAL_NAMESPACE` / `TOOL_REGISTRY` from the converter. Inspector findings from grclanker are pre-run JSON files dropped into `evidence/` — the pipeline imports them as another evidence source.

**Tech Stack:** Python 3.10+, boto3 (AWS), requests (NVD/GitHub API), Pillow (screenshot capture), existing openpyxl/python-docx

**Existing patterns to follow:**
- `OSCAL_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")` — same namespace everywhere
- `stable_uuid(name)` — deterministic UUIDs for clean diffs
- `TOOL_REGISTRY` — 10 tools, each with `controls`, `families`, `evidence_type`
- OSCAL structure: `ssp.json` has `system-security-plan.control-implementation.implemented-requirements[]`
- Each requirement has `props` including `control-origination`, `evidence-method`, `last-reconciled`
- `assessment-results.json` has `assessment-results.results[0].observations[]` and `.findings[]`
- `poam.json` has `plan-of-action-and-milestones.poam-items[]`

**AWS demo environment (created by `aws-setup.sh`):**
- 5 IAM users: `demo-compliant`, `demo-no-mfa` (no MFA), `demo-stale-key` (aging key), `workshop-admin`, `svc-pipeline`
- 4 S3 buckets: `workshop-encrypted-*` (compliant), `workshop-logging-*` (compliant), `workshop-open-*` (no encryption, no public block), `workshop-cloudtrail-*` (compliant)
- CloudTrail: `workshop-audit-trail` — multi-region, log file validation disabled
- AWS Config: recording all resource types

**Intentional findings the pipeline should detect:**
1. `demo-no-mfa` has no MFA → IA-2
2. `demo-stale-key` has aging access key → AC-2
3. `workshop-open-*` has no encryption → SC-28
4. CloudTrail log file validation disabled → AU-9
5. GitHub: no branch protection on main → CM-3
6. GitHub: no required PR reviews → CM-3, SA-11

---

### Task 1: Shared utilities module

**Files:**
- Create: `scripts/pipeline_utils.py`

This module holds shared constants and helpers used by all pipeline scripts, avoiding duplication of `OSCAL_NAMESPACE`, `stable_uuid`, `TOOL_REGISTRY`, and the screenshot renderer.

- [ ] **Step 1: Create `scripts/pipeline_utils.py` with shared constants**

```python
"""
pipeline_utils.py — Shared constants and helpers for the OSCAL pipeline.

Every pipeline script imports from here instead of duplicating
OSCAL_NAMESPACE, stable_uuid, TOOL_REGISTRY, and screenshot capture.
"""

import json
import os
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


# ── Tool Registry ─────────────────────────────────────────────────────────────
# Mirrors excel_to_oscal.py TOOL_REGISTRY. Single source of truth for the pipeline.

TOOL_REGISTRY = {
    "aws_iam": {
        "title": "AWS IAM",
        "type": "service",
        "families": ["ac", "ia"],
        "controls": ["ac-2", "ac-2(1)", "ac-3", "ac-5", "ac-6", "ac-6(1)", "ac-7",
                      "ia-2", "ia-2(1)", "ia-4", "ia-5", "ia-5(1)"],
        "evidence_type": "Cloud Identity & Access",
    },
    "aws_s3": {
        "title": "AWS S3 & KMS",
        "type": "service",
        "families": ["sc", "cp", "au"],
        "controls": ["sc-28", "sc-7", "sc-8", "sc-12", "sc-13", "cp-9", "au-9"],
        "evidence_type": "Data Encryption, Storage & Backup",
    },
    "aws_cloudtrail": {
        "title": "AWS CloudTrail",
        "type": "service",
        "families": ["au"],
        "controls": ["au-2", "au-3", "au-12"],
        "evidence_type": "Audit Logging",
    },
    "aws_config": {
        "title": "AWS Config",
        "type": "service",
        "families": ["cm", "pm", "ra"],
        "controls": ["cm-2", "cm-3", "cm-8", "ra-5", "sa-10"],
        "evidence_type": "Asset Discovery & Configuration Inventory",
    },
    "github": {
        "title": "GitHub",
        "type": "software",
        "families": ["cm", "sa"],
        "controls": ["cm-2", "cm-3", "cm-5", "cm-7", "cm-8", "sa-10"],
        "evidence_type": "Source Control & Change Management",
    },
    "github_actions": {
        "title": "GitHub Actions",
        "type": "software",
        "families": ["sa", "cm", "si"],
        "controls": ["sa-10", "sa-11", "cm-3", "si-2"],
        "evidence_type": "CI/CD Pipeline Security",
    },
    "codeql": {
        "title": "CodeQL (GitHub SAST)",
        "type": "software",
        "families": ["sa", "si"],
        "controls": ["sa-11", "si-2", "ra-5"],
        "evidence_type": "Static Application Security Testing",
    },
    "trivy": {
        "title": "Trivy (Open Source Scanner)",
        "type": "software",
        "families": ["ra", "si", "cm"],
        "controls": ["ra-5", "si-2", "cm-6", "cm-7"],
        "evidence_type": "Container, IaC & Dependency Scanning",
    },
    "nvd": {
        "title": "NIST NVD / OSV.dev",
        "type": "service",
        "families": ["ra", "si"],
        "controls": ["ra-5", "si-2"],
        "evidence_type": "Vulnerability Intelligence",
    },
    "prowler": {
        "title": "Prowler (Open Source CSPM)",
        "type": "software",
        "families": ["ac", "au", "cm", "ia", "ra", "sc", "si"],
        "controls": ["ac-2", "ac-3", "ac-6", "ac-7", "au-2", "au-9", "cm-6", "cm-7",
                      "ia-2", "ia-5", "ra-5", "sc-7", "sc-28", "si-4"],
        "evidence_type": "Cloud Security Posture Management",
    },
}


def get_tools_for_control(control_id: str) -> list:
    """Return tool keys whose control list includes this control."""
    tools = []
    for key, tool in TOOL_REGISTRY.items():
        if control_id in tool["controls"]:
            tools.append(key)
    return tools


# ── Screenshot capture ────────────────────────────────────────────────────────

def capture_screenshot(text: str, output_path: str) -> str:
    """
    Render CLI text output to a PNG image using Pillow.
    Returns the path to the saved PNG.
    """
    from PIL import Image, ImageDraw, ImageFont

    lines = text.split("\n")
    # Use a monospace font — Pillow's default, or Courier if available
    try:
        font = ImageFont.truetype("Courier", 14)
    except (OSError, IOError):
        try:
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 14)
        except (OSError, IOError):
            font = ImageFont.load_default()

    # Calculate image size
    char_width = 8
    line_height = 18
    padding = 20
    max_line_len = max((len(line) for line in lines), default=40)
    img_width = max(max_line_len * char_width + padding * 2, 400)
    img_height = len(lines) * line_height + padding * 2

    # Dark background, light text — looks like a terminal
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

- [ ] **Step 2: Verify the module loads**

Run: `cd /tmp/oscal-pipeline-workshop && python3 -c "from scripts.pipeline_utils import stable_uuid, TOOL_REGISTRY, capture_screenshot; print(f'Tools: {len(TOOL_REGISTRY)}'); print(f'UUID test: {stable_uuid(\"test\")}')"` 

Expected: `Tools: 10` and a UUID string.

- [ ] **Step 3: Commit**

```bash
git add scripts/pipeline_utils.py
git commit -m "feat: add shared pipeline utilities module

Extracts OSCAL_NAMESPACE, stable_uuid, TOOL_REGISTRY, screenshot
capture, and OSCAL helper functions into a shared module used by
all pipeline stages."
```

---

### Task 2: Discovery script

**Files:**
- Create: `scripts/discover.py`

Pulls real inventory from AWS Config and GitHub API, produces `oscal/inventory.json`, and detects drift against the SSP.

- [ ] **Step 1: Create `scripts/discover.py`**

```python
"""
discover.py — Stage 2: Discovery

Pulls a real inventory from AWS Config and GitHub, produces an
OSCAL-formatted inventory, and detects drift against the SSP.

USAGE:
  python discover.py --ssp oscal/ssp.json --output oscal/inventory.json
  python discover.py --help

REQUIRES:
  - boto3 (pip install boto3)
  - AWS credentials configured (via .env or aws configure)
  - GITHUB_TOKEN environment variable
  - GITHUB_ORG environment variable (org or username)
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import boto3
except ImportError:
    print("ERROR: boto3 not installed. Run: pip install boto3")
    sys.exit(1)

# Add scripts dir to path for imports
sys.path.insert(0, os.path.dirname(__file__))
from pipeline_utils import (
    stable_uuid, now_iso, load_oscal, save_oscal,
    capture_screenshot, TOOL_REGISTRY,
)


# ── AWS Config resource types we care about ──────────────────────────────────

AWS_RESOURCE_TYPES = [
    "AWS::IAM::User",
    "AWS::IAM::Role",
    "AWS::IAM::Policy",
    "AWS::S3::Bucket",
    "AWS::CloudTrail::Trail",
    "AWS::Config::ConfigurationRecorder",
    "AWS::EC2::Instance",
    "AWS::EC2::SecurityGroup",
    "AWS::EC2::VPC",
    "AWS::KMS::Key",
]


def discover_aws(region: str = "us-east-1") -> list:
    """Query AWS Config for discovered resources."""
    print("\n    Querying AWS Config for resources...")
    config_client = boto3.client("config", region_name=region)
    resources = []

    for resource_type in AWS_RESOURCE_TYPES:
        try:
            resp = config_client.list_discovered_resources(
                resourceType=resource_type,
                limit=100,
            )
            for r in resp.get("resourceIdentifiers", []):
                resources.append({
                    "type": r["resourceType"],
                    "id": r.get("resourceId", ""),
                    "name": r.get("resourceName", r.get("resourceId", "")),
                    "source": "aws_config",
                })
                print(f"      {r['resourceType']:40s} {r.get('resourceName', r.get('resourceId', ''))}")
        except Exception as e:
            print(f"      WARN: Could not list {resource_type}: {e}")

    print(f"\n    AWS resources discovered: {len(resources)}")
    return resources


def discover_github() -> list:
    """Query GitHub API for repos, branch protection, workflows."""
    token = os.environ.get("GITHUB_TOKEN")
    org = os.environ.get("GITHUB_ORG")

    if not token or not org:
        print("    WARN: GITHUB_TOKEN or GITHUB_ORG not set — skipping GitHub discovery")
        return []

    print(f"\n    Querying GitHub for org/user: {org}...")

    import requests
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    resources = []

    # List repos
    resp = requests.get(f"https://api.github.com/users/{org}/repos?per_page=100", headers=headers)
    if resp.status_code != 200:
        # Try org endpoint
        resp = requests.get(f"https://api.github.com/orgs/{org}/repos?per_page=100", headers=headers)

    if resp.status_code == 200:
        repos = resp.json()
        for repo in repos:
            resources.append({
                "type": "GitHub::Repository",
                "id": repo["full_name"],
                "name": repo["name"],
                "source": "github",
            })
            print(f"      GitHub::Repository                         {repo['name']}")

            # Check branch protection on default branch
            default_branch = repo.get("default_branch", "main")
            bp_resp = requests.get(
                f"https://api.github.com/repos/{repo['full_name']}/branches/{default_branch}/protection",
                headers=headers,
            )
            if bp_resp.status_code == 200:
                bp = bp_resp.json()
                resources.append({
                    "type": "GitHub::BranchProtection",
                    "id": f"{repo['full_name']}:{default_branch}",
                    "name": f"{repo['name']}/{default_branch} protection",
                    "source": "github",
                    "details": {
                        "required_reviews": bp.get("required_pull_request_reviews") is not None,
                        "status_checks": bp.get("required_status_checks") is not None,
                    },
                })
                print(f"      GitHub::BranchProtection                   {repo['name']}/{default_branch} ✓")
            elif bp_resp.status_code == 404:
                resources.append({
                    "type": "GitHub::BranchProtection",
                    "id": f"{repo['full_name']}:{default_branch}",
                    "name": f"{repo['name']}/{default_branch} protection",
                    "source": "github",
                    "details": {
                        "required_reviews": False,
                        "status_checks": False,
                        "missing": True,
                    },
                })
                print(f"      GitHub::BranchProtection                   {repo['name']}/{default_branch} ✗ (none)")

            # Check for workflows
            wf_resp = requests.get(
                f"https://api.github.com/repos/{repo['full_name']}/actions/workflows",
                headers=headers,
            )
            if wf_resp.status_code == 200:
                workflows = wf_resp.json().get("workflows", [])
                for wf in workflows:
                    resources.append({
                        "type": "GitHub::ActionsWorkflow",
                        "id": f"{repo['full_name']}:{wf['name']}",
                        "name": f"{repo['name']}/{wf['name']}",
                        "source": "github_actions",
                    })
                    print(f"      GitHub::ActionsWorkflow                    {repo['name']}/{wf['name']}")

    print(f"\n    GitHub resources discovered: {len(resources)}")
    return resources


def extract_ssp_components(ssp: dict) -> list:
    """Extract component names declared in the SSP."""
    components = []
    sys_impl = ssp.get("system-security-plan", {}).get("system-implementation", {})
    for comp in sys_impl.get("components", []):
        components.append({
            "title": comp.get("title", ""),
            "type": comp.get("type", ""),
            "uuid": comp.get("uuid", ""),
        })
    return components


def detect_drift(discovered: list, ssp_components: list) -> dict:
    """Compare discovered resources against SSP-declared components."""
    ssp_titles = {c["title"].lower() for c in ssp_components}

    # Map discovered resource sources to SSP component titles
    source_to_ssp = {
        "aws_config": ["aws iam", "aws s3 & kms", "aws cloudtrail", "aws config"],
        "github": ["github"],
        "github_actions": ["github actions"],
    }

    undocumented = []
    for resource in discovered:
        source = resource.get("source", "")
        expected_titles = source_to_ssp.get(source, [])
        if not any(t in ssp_titles for t in expected_titles):
            undocumented.append(resource)

    return {
        "total_discovered": len(discovered),
        "ssp_components": len(ssp_components),
        "undocumented": undocumented,
    }


def build_inventory(discovered: list, drift: dict) -> dict:
    """Build OSCAL-formatted inventory JSON."""
    components = []
    for r in discovered:
        components.append({
            "uuid": stable_uuid(f"inventory:{r['type']}:{r['id']}"),
            "type": r["type"],
            "title": r["name"],
            "props": [
                {"name": "source", "value": r["source"]},
                {"name": "resource-id", "value": r["id"]},
                {"name": "discovered-at", "value": now_iso()},
            ],
        })

    return {
        "inventory": {
            "uuid": stable_uuid("inventory:workshop"),
            "metadata": {
                "title": "Workshop Demo — Discovered Inventory",
                "last-modified": now_iso(),
                "version": "1.0.0",
            },
            "components": components,
            "drift-summary": {
                "total-discovered": drift["total_discovered"],
                "ssp-components": drift["ssp_components"],
                "undocumented-count": len(drift["undocumented"]),
                "undocumented": [
                    {"type": r["type"], "id": r["id"], "name": r["name"]}
                    for r in drift["undocumented"]
                ],
            },
        }
    }


def main():
    parser = argparse.ArgumentParser(description="Stage 2: Discover AWS + GitHub inventory")
    parser.add_argument("--ssp", default="oscal/ssp.json", help="Path to SSP JSON")
    parser.add_argument("--output", default="oscal/inventory.json", help="Output inventory path")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--screenshots", default="evidence/screenshots", help="Screenshot output dir")
    args = parser.parse_args()

    print(f"\n{'='*62}")
    print(f"  OSCAL Pipeline — Stage 2: DISCOVER")
    print(f"  What's actually in your environment?")
    print(f"{'='*62}")

    # Load SSP
    print(f"\n  Loading SSP: {args.ssp}")
    ssp = load_oscal(args.ssp)
    ssp_components = extract_ssp_components(ssp)
    print(f"    SSP declares {len(ssp_components)} components")

    # Discover
    aws_resources = discover_aws(args.region)
    github_resources = discover_github()
    all_resources = aws_resources + github_resources

    # Capture discovery output as screenshot
    discovery_text = f"DISCOVERY RESULTS\n{'='*50}\n"
    discovery_text += f"AWS resources:    {len(aws_resources)}\n"
    discovery_text += f"GitHub resources: {len(github_resources)}\n"
    discovery_text += f"Total discovered: {len(all_resources)}\n\n"
    for r in all_resources:
        discovery_text += f"  {r['type']:40s} {r['name']}\n"

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    screenshot_path = f"{args.screenshots}/discovery-inventory-{ts}.png"
    capture_screenshot(discovery_text, screenshot_path)
    print(f"\n    Screenshot: {screenshot_path}")

    # Drift detection
    drift = detect_drift(all_resources, ssp_components)

    # Build and save inventory
    inventory = build_inventory(all_resources, drift)
    save_oscal(inventory, args.output)

    # Summary
    print(f"\n{'='*62}")
    print(f"  DISCOVERY COMPLETE")
    print(f"{'='*62}")
    print(f"  Resources discovered:  {len(all_resources)}")
    print(f"    AWS:                 {len(aws_resources)}")
    print(f"    GitHub:              {len(github_resources)}")
    print(f"  SSP components:        {len(ssp_components)}")
    print(f"  Undocumented:          {len(drift['undocumented'])}")
    if drift["undocumented"]:
        print(f"\n  Undocumented resources (not in SSP):")
        for r in drift["undocumented"]:
            print(f"    ✗ {r['type']:40s} {r['name']}")
    print(f"\n  Output: {args.output}")
    print(f"{'='*62}\n")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Test import and --help**

Run: `cd /tmp/oscal-pipeline-workshop && python3 scripts/discover.py --help`

Expected: Help text showing `--ssp`, `--output`, `--region`, `--screenshots` options.

- [ ] **Step 3: Commit**

```bash
git add scripts/discover.py
git commit -m "feat: add discovery script (stage 2)

Queries AWS Config and GitHub API for real resource inventory,
compares against SSP-declared components, flags undocumented
resources as drift."
```

---

### Task 3: Assessment script

**Files:**
- Create: `scripts/assess.py`
- Create: `scripts/inspector_control_map.json`

Runs Prowler, Trivy, NVD, and CodeQL checks. Imports grclanker inspector findings. Captures screenshots. Maps everything to OSCAL controls.

- [ ] **Step 1: Create `scripts/inspector_control_map.json`**

```json
{
  "stale_access_key": ["ac-2"],
  "no_mfa": ["ia-2"],
  "excessive_permissions": ["ac-6"],
  "root_account_usage": ["ac-6(1)"],
  "guardduty_disabled": ["si-4"],
  "cloudtrail_not_multiregion": ["au-2", "au-3"],
  "cloudtrail_no_log_validation": ["au-9"],
  "config_recorder_disabled": ["cm-8"],
  "s3_no_encryption": ["sc-28"],
  "s3_public_access": ["sc-7"],
  "security_hub_disabled": ["si-4", "ra-5"],
  "access_analyzer_no_findings": ["ac-6"],
  "branch_protection_disabled": ["cm-3"],
  "no_required_reviews": ["cm-3", "sa-11"],
  "no_status_checks": ["sa-10", "cm-3"],
  "code_scanning_disabled": ["sa-11"],
  "dependabot_disabled": ["ra-5", "si-2"],
  "actions_no_workflow": ["sa-10"]
}
```

- [ ] **Step 2: Create `scripts/assess.py`**

```python
"""
assess.py — Stage 3: Assessment

Runs control-specific checks (Prowler, Trivy, NVD, CodeQL) and
imports pre-run grclanker inspector findings. Captures CLI output
as PNG screenshots. Maps all findings to OSCAL controls.

USAGE:
  python assess.py --ssp oscal/ssp.json --output oscal/assessment-results.json
  python assess.py --help

REQUIRES:
  - boto3, requests, Pillow
  - prowler (pip install prowler) — optional, skipped if not installed
  - trivy — optional, skipped if not installed
  - AWS credentials + GITHUB_TOKEN in environment
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import boto3
    import requests
except ImportError:
    print("ERROR: boto3 and requests required. Run: pip install boto3 requests")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(__file__))
from pipeline_utils import (
    stable_uuid, now_iso, now_filesafe, load_oscal, save_oscal,
    capture_screenshot, make_observation, make_finding,
    TOOL_REGISTRY,
)


# ── AWS direct checks ────────────────────────────────────────────────────────

def check_iam(region: str) -> list:
    """Check IAM users for MFA, stale keys, password policy."""
    print("\n    [IAM] Checking users, MFA, access keys...")
    findings = []
    iam = boto3.client("iam", region_name=region)

    # Password policy
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        desc = (f"MinLength={policy.get('MinimumPasswordLength')}, "
                f"MaxAge={policy.get('MaxPasswordAge', 'none')}, "
                f"RequireSymbols={policy.get('RequireSymbols')}")
        findings.append({
            "source": "aws_iam", "control": "ia-5",
            "status": "pass", "title": "Password policy configured",
            "description": desc,
        })
        print(f"      Password policy: {desc} ✓")
    except iam.exceptions.NoSuchEntityException:
        findings.append({
            "source": "aws_iam", "control": "ia-5",
            "status": "fail", "title": "No password policy set",
            "description": "Account has no custom password policy configured.",
        })
        print(f"      Password policy: none ✗")

    # Users
    users = iam.list_users()["Users"]
    for user in users:
        username = user["UserName"]

        # MFA check
        mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
        if not mfa_devices:
            findings.append({
                "source": "aws_iam", "control": "ia-2",
                "status": "fail", "title": f"No MFA: {username}",
                "description": f"IAM user '{username}' has no MFA device enabled.",
            })
            print(f"      {username}: no MFA ✗")
        else:
            findings.append({
                "source": "aws_iam", "control": "ia-2",
                "status": "pass", "title": f"MFA enabled: {username}",
                "description": f"IAM user '{username}' has MFA enabled.",
            })
            print(f"      {username}: MFA enabled ✓")

        # Access key age
        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        for key in keys:
            age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days
            if age_days > 90:
                findings.append({
                    "source": "aws_iam", "control": "ac-2",
                    "status": "fail",
                    "title": f"Stale access key: {username}",
                    "description": f"IAM user '{username}' access key is {age_days} days old (>90 day threshold).",
                })
                print(f"      {username}: access key {age_days}d old ✗")
            elif keys:
                findings.append({
                    "source": "aws_iam", "control": "ac-2",
                    "status": "pass",
                    "title": f"Access key OK: {username}",
                    "description": f"IAM user '{username}' access key is {age_days} days old.",
                })
                print(f"      {username}: access key {age_days}d old ✓")

    return findings


def check_s3(region: str) -> list:
    """Check S3 buckets for encryption and public access."""
    print("\n    [S3] Checking buckets for encryption and public access...")
    findings = []
    s3 = boto3.client("s3", region_name=region)

    buckets = s3.list_buckets()["Buckets"]
    for bucket in buckets:
        name = bucket["Name"]
        if not name.startswith("workshop-"):
            continue

        # Encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
            findings.append({
                "source": "aws_s3", "control": "sc-28",
                "status": "pass", "title": f"Encrypted: {name}",
                "description": f"S3 bucket '{name}' has server-side encryption enabled.",
            })
            print(f"      {name}: encrypted ✓")
        except s3.exceptions.ClientError as e:
            if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                findings.append({
                    "source": "aws_s3", "control": "sc-28",
                    "status": "fail", "title": f"No encryption: {name}",
                    "description": f"S3 bucket '{name}' has no server-side encryption configured.",
                })
                print(f"      {name}: no encryption ✗")

        # Public access block
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            all_blocked = all([
                pab.get("BlockPublicAcls", False),
                pab.get("IgnorePublicAcls", False),
                pab.get("BlockPublicPolicy", False),
                pab.get("RestrictPublicBuckets", False),
            ])
            if all_blocked:
                findings.append({
                    "source": "aws_s3", "control": "sc-7",
                    "status": "pass", "title": f"Public access blocked: {name}",
                    "description": f"S3 bucket '{name}' has all public access blocks enabled.",
                })
                print(f"      {name}: public access blocked ✓")
            else:
                findings.append({
                    "source": "aws_s3", "control": "sc-7",
                    "status": "fail", "title": f"Partial public block: {name}",
                    "description": f"S3 bucket '{name}' has incomplete public access blocks.",
                })
                print(f"      {name}: partial public block ✗")
        except s3.exceptions.ClientError:
            findings.append({
                "source": "aws_s3", "control": "sc-7",
                "status": "fail", "title": f"No public access block: {name}",
                "description": f"S3 bucket '{name}' has no public access block configuration.",
            })
            print(f"      {name}: no public access block ✗")

    return findings


def check_cloudtrail(region: str) -> list:
    """Check CloudTrail configuration."""
    print("\n    [CloudTrail] Checking trail configuration...")
    findings = []
    ct = boto3.client("cloudtrail", region_name=region)

    trails = ct.describe_trails()["trailList"]
    for trail in trails:
        name = trail["Name"]
        is_multi = trail.get("IsMultiRegionTrail", False)
        has_validation = trail.get("LogFileValidationEnabled", False)

        # Multi-region
        if is_multi:
            findings.append({
                "source": "aws_cloudtrail", "control": "au-2",
                "status": "pass", "title": f"Multi-region: {name}",
                "description": f"CloudTrail '{name}' is configured for multi-region logging.",
            })
            print(f"      {name}: multi-region ✓")
        else:
            findings.append({
                "source": "aws_cloudtrail", "control": "au-2",
                "status": "fail", "title": f"Single-region: {name}",
                "description": f"CloudTrail '{name}' is NOT multi-region.",
            })
            print(f"      {name}: single-region ✗")

        # Log file validation
        if has_validation:
            findings.append({
                "source": "aws_cloudtrail", "control": "au-9",
                "status": "pass", "title": f"Log validation: {name}",
                "description": f"CloudTrail '{name}' has log file validation enabled.",
            })
            print(f"      {name}: log validation ✓")
        else:
            findings.append({
                "source": "aws_cloudtrail", "control": "au-9",
                "status": "fail", "title": f"No log validation: {name}",
                "description": f"CloudTrail '{name}' has log file validation DISABLED.",
            })
            print(f"      {name}: no log validation ✗")

        # Logging status
        status = ct.get_trail_status(Name=trail["TrailARN"])
        if status.get("IsLogging", False):
            findings.append({
                "source": "aws_cloudtrail", "control": "au-12",
                "status": "pass", "title": f"Logging active: {name}",
                "description": f"CloudTrail '{name}' is actively logging.",
            })
            print(f"      {name}: logging active ✓")
        else:
            findings.append({
                "source": "aws_cloudtrail", "control": "au-12",
                "status": "fail", "title": f"Logging stopped: {name}",
                "description": f"CloudTrail '{name}' is NOT logging.",
            })
            print(f"      {name}: logging stopped ✗")

    return findings


def check_github_security() -> list:
    """Check GitHub repo security: branch protection, code scanning."""
    token = os.environ.get("GITHUB_TOKEN")
    org = os.environ.get("GITHUB_ORG")
    if not token or not org:
        print("\n    [GitHub] WARN: GITHUB_TOKEN or GITHUB_ORG not set — skipping")
        return []

    print(f"\n    [GitHub] Checking repos for {org}...")
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    findings = []

    resp = requests.get(f"https://api.github.com/users/{org}/repos?per_page=100", headers=headers)
    if resp.status_code != 200:
        resp = requests.get(f"https://api.github.com/orgs/{org}/repos?per_page=100", headers=headers)
    if resp.status_code != 200:
        print(f"      WARN: Could not list repos: {resp.status_code}")
        return []

    repos = resp.json()
    for repo in repos:
        name = repo["full_name"]
        default_branch = repo.get("default_branch", "main")

        # Branch protection
        bp_resp = requests.get(
            f"https://api.github.com/repos/{name}/branches/{default_branch}/protection",
            headers=headers,
        )
        if bp_resp.status_code == 200:
            bp = bp_resp.json()
            # Required reviews
            if bp.get("required_pull_request_reviews"):
                findings.append({
                    "source": "github", "control": "cm-3",
                    "status": "pass", "title": f"Required reviews: {repo['name']}",
                    "description": f"Repo '{name}' requires PR reviews on {default_branch}.",
                })
                print(f"      {repo['name']}: required reviews ✓")
            else:
                findings.append({
                    "source": "github", "control": "cm-3",
                    "status": "fail", "title": f"No required reviews: {repo['name']}",
                    "description": f"Repo '{name}' does NOT require PR reviews on {default_branch}.",
                })
                findings.append({
                    "source": "github", "control": "sa-11",
                    "status": "fail", "title": f"No code review gate: {repo['name']}",
                    "description": f"Repo '{name}' has no required review gate on {default_branch}.",
                })
                print(f"      {repo['name']}: no required reviews ✗")
        elif bp_resp.status_code == 404:
            findings.append({
                "source": "github", "control": "cm-3",
                "status": "fail", "title": f"No branch protection: {repo['name']}",
                "description": f"Repo '{name}' has NO branch protection on {default_branch}.",
            })
            print(f"      {repo['name']}: no branch protection ✗")

        # Code scanning (CodeQL)
        cs_resp = requests.get(
            f"https://api.github.com/repos/{name}/code-scanning/alerts?state=open&per_page=1",
            headers=headers,
        )
        if cs_resp.status_code == 200:
            alerts = cs_resp.json()
            if alerts:
                findings.append({
                    "source": "codeql", "control": "sa-11",
                    "status": "fail", "title": f"Open code scanning alerts: {repo['name']}",
                    "description": f"Repo '{name}' has open code scanning alerts.",
                })
                print(f"      {repo['name']}: open code scanning alerts ✗")
            else:
                findings.append({
                    "source": "codeql", "control": "sa-11",
                    "status": "pass", "title": f"No code scanning alerts: {repo['name']}",
                    "description": f"Repo '{name}' has no open code scanning alerts.",
                })
                print(f"      {repo['name']}: code scanning clean ✓")
        elif cs_resp.status_code == 404:
            findings.append({
                "source": "codeql", "control": "sa-11",
                "status": "fail", "title": f"Code scanning not enabled: {repo['name']}",
                "description": f"Repo '{name}' does not have code scanning enabled.",
            })
            print(f"      {repo['name']}: code scanning not enabled ✗")

    return findings


def run_prowler(region: str) -> list:
    """Run Prowler if installed, parse JSON output."""
    print("\n    [Prowler] Checking if installed...")
    try:
        result = subprocess.run(["prowler", "--version"], capture_output=True, text=True)
        if result.returncode != 0:
            print("      Prowler not found — skipping")
            return []
    except FileNotFoundError:
        print("      Prowler not found — skipping")
        return []

    print(f"      Running Prowler (this may take a few minutes)...")
    prowler_output = Path("evidence/prowler-output")
    prowler_output.mkdir(parents=True, exist_ok=True)

    result = subprocess.run(
        ["prowler", "aws", "--region", region, "--output-formats", "json",
         "--output-directory", str(prowler_output), "--no-banner"],
        capture_output=True, text=True, timeout=600,
    )

    findings = []
    # Find the JSON output file
    json_files = list(prowler_output.glob("*.json"))
    if not json_files:
        print("      No Prowler output file found")
        return findings

    with open(json_files[0]) as f:
        for line in f:
            try:
                check = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            status = "pass" if check.get("StatusExtended", "").startswith("PASS") else "fail"
            # Map Prowler check to OSCAL control via compliance mapping
            control = None
            compliance = check.get("Compliance", {})
            for framework, controls in compliance.items():
                if "800-53" in framework or "fedramp" in framework.lower():
                    if controls:
                        control = controls[0].lower()
                        break

            if not control:
                continue

            findings.append({
                "source": "prowler",
                "control": control,
                "status": status,
                "title": check.get("CheckTitle", "Prowler check"),
                "description": check.get("StatusExtended", ""),
            })

    print(f"      Prowler findings: {len(findings)}")
    return findings


def run_trivy() -> list:
    """Run Trivy filesystem scan if installed."""
    print("\n    [Trivy] Checking if installed...")
    try:
        result = subprocess.run(["trivy", "--version"], capture_output=True, text=True)
        if result.returncode != 0:
            print("      Trivy not found — skipping")
            return []
    except FileNotFoundError:
        print("      Trivy not found — skipping")
        return []

    print(f"      Running Trivy filesystem scan...")
    result = subprocess.run(
        ["trivy", "fs", "--format", "json", "--scanners", "vuln,misconfig", "."],
        capture_output=True, text=True, timeout=300,
    )

    findings = []
    if result.returncode == 0 and result.stdout:
        try:
            trivy_data = json.loads(result.stdout)
            for target in trivy_data.get("Results", []):
                for vuln in target.get("Vulnerabilities", []):
                    findings.append({
                        "source": "trivy",
                        "control": "ra-5",
                        "status": "fail",
                        "title": f"CVE: {vuln.get('VulnerabilityID', 'unknown')}",
                        "description": (f"{vuln.get('PkgName', '')}: {vuln.get('Title', '')} "
                                        f"(severity: {vuln.get('Severity', 'unknown')})"),
                    })
                for misconfig in target.get("Misconfigurations", []):
                    findings.append({
                        "source": "trivy",
                        "control": "cm-6",
                        "status": "fail" if misconfig.get("Status") == "FAIL" else "pass",
                        "title": f"Misconfig: {misconfig.get('ID', 'unknown')}",
                        "description": misconfig.get("Message", ""),
                    })
        except json.JSONDecodeError:
            print("      WARN: Could not parse Trivy output")

    print(f"      Trivy findings: {len(findings)}")
    return findings


def check_nvd(inventory_path: str) -> list:
    """Query NVD for known CVEs against discovered components."""
    print("\n    [NVD] Checking for known vulnerabilities...")
    findings = []

    # Query NVD for common workshop components
    keywords = ["boto3", "openpyxl", "python-docx", "pillow"]
    for keyword in keywords:
        try:
            resp = requests.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=5",
                timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                total = data.get("totalResults", 0)
                if total > 0:
                    for cve in data.get("vulnerabilities", [])[:3]:
                        cve_id = cve["cve"]["id"]
                        desc_list = cve["cve"].get("descriptions", [])
                        desc = desc_list[0]["value"] if desc_list else "No description"
                        findings.append({
                            "source": "nvd",
                            "control": "ra-5",
                            "status": "fail",
                            "title": f"{cve_id}: {keyword}",
                            "description": desc[:200],
                        })
                        print(f"      {cve_id} ({keyword})")
                else:
                    findings.append({
                        "source": "nvd",
                        "control": "ra-5",
                        "status": "pass",
                        "title": f"No CVEs: {keyword}",
                        "description": f"No known CVEs found for '{keyword}' in NVD.",
                    })
                    print(f"      {keyword}: no known CVEs ✓")
        except Exception as e:
            print(f"      WARN: NVD query failed for {keyword}: {e}")

    return findings


def import_inspector_findings(evidence_dir: str) -> list:
    """Import pre-run grclanker inspector findings."""
    print("\n    [Inspector] Importing grclanker findings...")
    findings = []

    map_path = os.path.join(os.path.dirname(__file__), "inspector_control_map.json")
    if not os.path.exists(map_path):
        print("      WARN: inspector_control_map.json not found — skipping")
        return findings

    with open(map_path) as f:
        control_map = json.load(f)

    inspector_files = {
        "aws-inspector-findings.json": "aws-sec-inspector",
        "github-inspector-findings.json": "github-sec-inspector",
    }

    for filename, source in inspector_files.items():
        filepath = os.path.join(evidence_dir, filename)
        if not os.path.exists(filepath):
            print(f"      {filename}: not found — skipping")
            continue

        with open(filepath) as f:
            inspector_data = json.load(f)

        count = 0
        for item in inspector_data if isinstance(inspector_data, list) else inspector_data.get("findings", []):
            finding_type = item.get("type", item.get("finding_type", ""))
            controls = control_map.get(finding_type, [])

            for control in controls:
                findings.append({
                    "source": source,
                    "control": control,
                    "status": item.get("status", "fail"),
                    "title": item.get("title", finding_type),
                    "description": item.get("description", ""),
                })
                count += 1

        print(f"      {filename}: {count} findings imported")

    return findings


def main():
    parser = argparse.ArgumentParser(description="Stage 3: Assess controls against live evidence")
    parser.add_argument("--ssp", default="oscal/ssp.json", help="Path to SSP JSON")
    parser.add_argument("--output", default="oscal/assessment-results.json", help="Output path")
    parser.add_argument("--evidence", default="evidence", help="Evidence directory")
    parser.add_argument("--screenshots", default="evidence/screenshots", help="Screenshot dir")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--skip-prowler", action="store_true", help="Skip Prowler scan")
    parser.add_argument("--skip-trivy", action="store_true", help="Skip Trivy scan")
    parser.add_argument("--skip-nvd", action="store_true", help="Skip NVD lookup")
    args = parser.parse_args()

    print(f"\n{'='*62}")
    print(f"  OSCAL Pipeline — Stage 3: ASSESS")
    print(f"  Running checks against live environment")
    print(f"{'='*62}")

    all_findings = []

    # AWS direct checks (always run — these are the core workshop checks)
    all_findings.extend(check_iam(args.region))
    all_findings.extend(check_s3(args.region))
    all_findings.extend(check_cloudtrail(args.region))

    # GitHub checks
    all_findings.extend(check_github_security())

    # Optional tool checks
    if not args.skip_prowler:
        all_findings.extend(run_prowler(args.region))
    if not args.skip_trivy:
        all_findings.extend(run_trivy())
    if not args.skip_nvd:
        all_findings.extend(check_nvd("oscal/inventory.json"))

    # Import grclanker inspector findings
    all_findings.extend(import_inspector_findings(args.evidence))

    # Build OSCAL assessment results
    ssp = load_oscal(args.ssp)
    ar = load_oscal(args.output) if os.path.exists(args.output) else {
        "assessment-results": {
            "uuid": stable_uuid("assessment-results:workshop"),
            "metadata": {
                "title": "Workshop Demo — Assessment Results",
                "last-modified": now_iso(),
                "version": "1.0.0",
                "oscal-version": "1.1.2",
            },
            "import-ap": {"href": "#"},
            "results": [{
                "uuid": stable_uuid("result:workshop-run"),
                "title": "Workshop Pipeline Run",
                "description": "Evidence collected against FedRAMP Moderate baseline.",
                "start": now_iso(),
                "reviewed-controls": {"control-selections": [{"include-all": {}}]},
                "observations": [],
                "findings": [],
            }],
        }
    }

    result = ar["assessment-results"]["results"][0]
    result["start"] = now_iso()
    result["observations"] = []
    result["findings"] = []

    # Convert raw findings to OSCAL observations + findings
    ts = now_filesafe()
    pass_count = 0
    fail_count = 0

    for i, f in enumerate(all_findings):
        obs_name = f"obs:{f['source']}:{f['control']}:{i}"
        finding_name = f"finding:{f['source']}:{f['control']}:{i}"

        # Screenshot
        screenshot_path = None
        screenshot_text = f"{f['title']}\n{'='*50}\nSource: {f['source']}\nControl: {f['control'].upper()}\nStatus: {f['status'].upper()}\n\n{f['description']}"
        screenshot_file = f"{args.screenshots}/{f['control'].upper()}-{f['source']}-{ts}.png"

        # Only capture individual screenshots for failures to keep things manageable
        if f["status"] == "fail":
            capture_screenshot(screenshot_text, screenshot_file)
            screenshot_path = screenshot_file

        obs = make_observation(
            obs_name, f["title"], f["description"],
            f["source"], f["control"], f["status"], screenshot_path,
        )
        result["observations"].append(obs)

        finding = make_finding(
            finding_name, f["title"], f["description"],
            f["control"], "not-satisfied" if f["status"] == "fail" else "satisfied",
            f["source"], [obs["uuid"]],
        )
        result["findings"].append(finding)

        if f["status"] == "pass":
            pass_count += 1
        else:
            fail_count += 1

    ar["assessment-results"]["metadata"]["last-modified"] = now_iso()

    # Save
    save_oscal(ar, args.output)

    # Summary screenshot
    summary_text = f"ASSESSMENT SUMMARY\n{'='*50}\n"
    summary_text += f"Total checks:  {len(all_findings)}\n"
    summary_text += f"Passed:        {pass_count}\n"
    summary_text += f"Failed:        {fail_count}\n\n"
    summary_text += f"By source:\n"
    sources = {}
    for f in all_findings:
        src = f["source"]
        if src not in sources:
            sources[src] = {"pass": 0, "fail": 0}
        sources[src][f["status"]] += 1
    for src, counts in sorted(sources.items()):
        summary_text += f"  {src:25s} pass={counts['pass']:3d}  fail={counts['fail']:3d}\n"
    summary_text += f"\nFailed checks:\n"
    for f in all_findings:
        if f["status"] == "fail":
            summary_text += f"  ✗ [{f['control'].upper():8s}] {f['title']}\n"

    capture_screenshot(summary_text, f"{args.screenshots}/assessment-summary-{ts}.png")

    # Console summary
    print(f"\n{'='*62}")
    print(f"  ASSESSMENT COMPLETE")
    print(f"{'='*62}")
    print(f"  Total checks:      {len(all_findings)}")
    print(f"  Passed:            {pass_count}")
    print(f"  Failed:            {fail_count}")
    print(f"{'─'*62}")
    print(f"  By source:")
    for src, counts in sorted(sources.items()):
        total = counts["pass"] + counts["fail"]
        print(f"    {src:25s} {total:3d} checks  ({counts['fail']} failed)")
    print(f"{'─'*62}")
    if fail_count > 0:
        print(f"\n  Failed checks:")
        for f in all_findings:
            if f["status"] == "fail":
                print(f"    ✗ [{f['control'].upper():8s}] [{f['source']:20s}] {f['title']}")
    print(f"\n  Output: {args.output}")
    print(f"  Screenshots: {args.screenshots}/")
    print(f"{'='*62}\n")


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Test import and --help**

Run: `cd /tmp/oscal-pipeline-workshop && python3 scripts/assess.py --help`

Expected: Help text showing all options including `--skip-prowler`, `--skip-trivy`, `--skip-nvd`.

- [ ] **Step 4: Commit**

```bash
git add scripts/assess.py scripts/inspector_control_map.json
git commit -m "feat: add assessment script (stage 3)

Runs IAM, S3, CloudTrail, GitHub checks directly via API.
Optionally runs Prowler, Trivy, NVD scans. Imports pre-run
grclanker inspector findings. Captures CLI screenshots.
Maps all findings to OSCAL controls."
```

---

### Task 4: Reconciliation script

**Files:**
- Create: `scripts/reconcile.py`

Compares SSP claims against assessment evidence. Produces populated assessment-results.json and poam.json.

- [ ] **Step 1: Create `scripts/reconcile.py`**

```python
"""
reconcile.py — Stage 4: Reconcile

Compares SSP claims (what you say) against assessment evidence
(what's actually true). Anything that doesn't match becomes a
POA&M item.

USAGE:
  python reconcile.py --ssp oscal/ssp.json --results oscal/assessment-results.json --output oscal/poam.json
  python reconcile.py --help
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from pipeline_utils import (
    stable_uuid, now_iso, now_filesafe, load_oscal, save_oscal,
    capture_screenshot, make_poam_item,
)


def extract_ssp_claims(ssp: dict) -> dict:
    """Extract control claims from the SSP."""
    claims = {}
    reqs = (ssp.get("system-security-plan", {})
            .get("control-implementation", {})
            .get("implemented-requirements", []))

    for req in reqs:
        control_id = req.get("control-id", "")
        props = {p["name"]: p["value"] for p in req.get("props", [])}
        claims[control_id] = {
            "status": props.get("control-origination", "unknown"),
            "evidence_method": props.get("evidence-method", "unknown"),
            "narrative": props.get("baseline-narrative", ""),
        }
    return claims


def extract_findings_by_control(ar: dict) -> dict:
    """Group assessment findings by control ID."""
    by_control = {}
    results = ar.get("assessment-results", {}).get("results", [])
    if not results:
        return by_control

    for finding in results[0].get("findings", []):
        target = finding.get("target", {})
        control_id = target.get("target-id", "")
        if not control_id:
            # Try props
            for p in finding.get("props", []):
                if p["name"] == "control-id":
                    control_id = p["value"]
                    break
        if not control_id:
            continue

        if control_id not in by_control:
            by_control[control_id] = []
        by_control[control_id].append({
            "status": target.get("status", {}).get("state", "unknown"),
            "title": finding.get("title", ""),
            "description": finding.get("description", ""),
            "source": next(
                (p["value"] for p in finding.get("props", []) if p["name"] == "source"),
                "unknown"
            ),
        })
    return by_control


def reconcile(claims: dict, findings_by_control: dict, inventory: dict = None) -> dict:
    """
    Compare SSP claims against evidence.
    Returns reconciliation results organized by control.
    """
    results = {}

    for control_id, claim in claims.items():
        control_findings = findings_by_control.get(control_id, [])

        has_evidence = len(control_findings) > 0
        has_failures = any(f["status"] == "not-satisfied" for f in control_findings)
        all_pass = has_evidence and not has_failures

        if claim["status"] == "inherited":
            verdict = "inherited"
        elif claim["status"] == "implemented" and all_pass:
            verdict = "confirmed"
        elif claim["status"] == "implemented" and has_failures:
            verdict = "contradicted"
        elif claim["status"] == "implemented" and not has_evidence:
            verdict = "unverified"
        elif claim["status"] == "planned":
            verdict = "planned"
        else:
            verdict = "unknown"

        results[control_id] = {
            "claim": claim["status"],
            "verdict": verdict,
            "evidence_count": len(control_findings),
            "failures": [f for f in control_findings if f["status"] == "not-satisfied"],
            "passes": [f for f in control_findings if f["status"] == "satisfied"],
            "sources": list(set(f["source"] for f in control_findings)),
        }

    return results


def build_poam(reconciliation: dict) -> list:
    """Build POA&M items from reconciliation failures and gaps."""
    poam_items = []

    for control_id, result in sorted(reconciliation.items()):
        if result["verdict"] == "contradicted":
            for failure in result["failures"]:
                poam_items.append(make_poam_item(
                    f"poam:{control_id}:{failure['source']}:{failure['title'][:30]}",
                    f"{control_id.upper()}: {failure['title']}",
                    failure["description"],
                    control_id,
                    failure["source"],
                ))
        elif result["verdict"] == "unverified":
            poam_items.append(make_poam_item(
                f"poam:{control_id}:unverified",
                f"{control_id.upper()}: Unverified claim — no evidence",
                (f"SSP claims '{result['claim']}' for {control_id.upper()} "
                 f"but no assessment evidence exists to confirm or deny."),
                control_id,
                "reconciler",
            ))

    return poam_items


def main():
    parser = argparse.ArgumentParser(description="Stage 4: Reconcile SSP claims vs evidence")
    parser.add_argument("--ssp", default="oscal/ssp.json", help="Path to SSP JSON")
    parser.add_argument("--results", default="oscal/assessment-results.json", help="Assessment results")
    parser.add_argument("--inventory", default="oscal/inventory.json", help="Inventory JSON")
    parser.add_argument("--output", default="oscal/poam.json", help="POA&M output path")
    parser.add_argument("--screenshots", default="evidence/screenshots", help="Screenshot dir")
    args = parser.parse_args()

    print(f"\n{'='*62}")
    print(f"  OSCAL Pipeline — Stage 4: RECONCILE")
    print(f"  SSP claims vs assessment evidence")
    print(f"{'='*62}")

    # Load inputs
    print(f"\n  Loading SSP: {args.ssp}")
    ssp = load_oscal(args.ssp)
    claims = extract_ssp_claims(ssp)
    print(f"    {len(claims)} control claims extracted")

    print(f"  Loading assessment results: {args.results}")
    ar = load_oscal(args.results)
    findings_by_control = extract_findings_by_control(ar)
    print(f"    Findings cover {len(findings_by_control)} controls")

    inventory = None
    if os.path.exists(args.inventory):
        print(f"  Loading inventory: {args.inventory}")
        inventory = load_oscal(args.inventory)

    # Reconcile
    print(f"\n  Reconciling...")
    reconciliation = reconcile(claims, findings_by_control, inventory)

    # Build POA&M
    poam_items = build_poam(reconciliation)

    # Update assessment-results with reconciliation verdicts
    results = ar["assessment-results"]["results"][0]
    for obs in results.get("observations", []):
        control_id = None
        for p in obs.get("props", []):
            if p["name"] == "control-id":
                control_id = p["value"]
                break
        if control_id and control_id in reconciliation:
            obs["props"].append({
                "name": "reconciliation-verdict",
                "value": reconciliation[control_id]["verdict"],
            })

    ar["assessment-results"]["metadata"]["last-modified"] = now_iso()
    save_oscal(ar, args.results)

    # Write POA&M
    poam = {
        "plan-of-action-and-milestones": {
            "uuid": stable_uuid("poam:workshop"),
            "metadata": {
                "title": "Workshop Demo — Plan of Action and Milestones",
                "last-modified": now_iso(),
                "version": "1.0.0",
                "oscal-version": "1.1.2",
            },
            "import-ssp": {"href": "ssp.json"},
            "poam-items": poam_items,
        }
    }
    save_oscal(poam, args.output)

    # Count verdicts
    verdicts = {}
    for r in reconciliation.values():
        v = r["verdict"]
        verdicts[v] = verdicts.get(v, 0) + 1

    # Screenshot
    ts = now_filesafe()
    summary_text = f"RECONCILIATION RESULTS\n{'='*50}\n\n"
    summary_text += f"Controls assessed: {len(reconciliation)}\n\n"
    summary_text += f"Verdicts:\n"
    for v, count in sorted(verdicts.items()):
        symbol = {"confirmed": "✓", "contradicted": "✗", "unverified": "?",
                  "inherited": "→", "planned": "◯"}.get(v, " ")
        summary_text += f"  {symbol} {v:15s} {count}\n"
    summary_text += f"\nPOA&M items: {len(poam_items)}\n"
    if poam_items:
        summary_text += f"\n"
        for item in poam_items:
            summary_text += f"  ✗ {item['title']}\n"

    capture_screenshot(summary_text, f"{args.screenshots}/reconciliation-summary-{ts}.png")

    # Console summary
    print(f"\n{'='*62}")
    print(f"  RECONCILIATION COMPLETE")
    print(f"{'='*62}")
    print(f"  Controls assessed:     {len(reconciliation)}")
    print(f"{'─'*62}")
    print(f"  Verdicts:")
    for v, count in sorted(verdicts.items()):
        symbol = {"confirmed": "✓", "contradicted": "✗", "unverified": "?",
                  "inherited": "→", "planned": "◯"}.get(v, " ")
        print(f"    {symbol} {v:15s} {count}")
    print(f"{'─'*62}")
    print(f"  POA&M items:           {len(poam_items)}")
    if poam_items:
        print(f"\n  POA&M details:")
        for item in poam_items:
            source = next((p["value"] for p in item["props"] if p["name"] == "source"), "?")
            print(f"    ✗ [{source:20s}] {item['title']}")
    print(f"\n  Updated: {args.results}")
    print(f"  Written:  {args.output}")
    print(f"{'='*62}\n")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Test import and --help**

Run: `cd /tmp/oscal-pipeline-workshop && python3 scripts/reconcile.py --help`

Expected: Help text showing `--ssp`, `--results`, `--inventory`, `--output`, `--screenshots`.

- [ ] **Step 3: Commit**

```bash
git add scripts/reconcile.py
git commit -m "feat: add reconciliation script (stage 4)

Compares SSP claims against assessment evidence. Controls are
marked confirmed, contradicted, or unverified. Contradictions
and gaps become POA&M items with source attribution."
```

---

### Task 5: Enforcement script

**Files:**
- Create: `scripts/enforce.py`

Reads assessment results and POA&M, prints pass/fail summary, optionally opens a GitHub issue.

- [ ] **Step 1: Create `scripts/enforce.py`**

```python
"""
enforce.py — Stage 5: Enforce

Reads assessment-results.json and poam.json, prints a pass/fail
summary, and optionally opens a GitHub issue for failures.

USAGE:
  python enforce.py --results oscal/assessment-results.json --poam oscal/poam.json
  python enforce.py --help

EXIT CODES:
  0 — all controls confirmed, no open POA&M items
  1 — findings exist
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))
from pipeline_utils import load_oscal, now_iso


def count_findings(ar: dict) -> dict:
    """Count findings by status."""
    counts = {"satisfied": 0, "not-satisfied": 0}
    results = ar.get("assessment-results", {}).get("results", [])
    if not results:
        return counts

    for finding in results[0].get("findings", []):
        status = finding.get("target", {}).get("status", {}).get("state", "unknown")
        counts[status] = counts.get(status, 0) + 1

    return counts


def get_failed_findings(ar: dict) -> list:
    """Get all failed findings with details."""
    failed = []
    results = ar.get("assessment-results", {}).get("results", [])
    if not results:
        return failed

    for finding in results[0].get("findings", []):
        status = finding.get("target", {}).get("status", {}).get("state", "")
        if status == "not-satisfied":
            source = next(
                (p["value"] for p in finding.get("props", []) if p["name"] == "source"),
                "unknown"
            )
            control = finding.get("target", {}).get("target-id", "unknown")
            failed.append({
                "control": control,
                "source": source,
                "title": finding.get("title", ""),
                "description": finding.get("description", ""),
            })
    return failed


def create_github_issue(poam_items: list, failed_findings: list, repo: str = None):
    """Create a GitHub issue with the finding summary."""
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("    WARN: GITHUB_TOKEN not set — skipping issue creation")
        return

    if not repo:
        org = os.environ.get("GITHUB_ORG", "")
        repo = f"{org}/oscal-pipeline-workshop" if org else None
    if not repo:
        print("    WARN: Could not determine repo — skipping issue creation")
        return

    import requests

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    title = f"[Pipeline] {len(poam_items)} findings — {today}"

    body = f"## Pipeline Assessment Results\n\n"
    body += f"**Date:** {today}\n"
    body += f"**POA&M items:** {len(poam_items)}\n"
    body += f"**Failed checks:** {len(failed_findings)}\n\n"

    body += f"### Failed Checks\n\n"
    body += f"| Control | Source | Finding |\n"
    body += f"|---------|--------|----------|\n"
    for f in failed_findings:
        body += f"| {f['control'].upper()} | {f['source']} | {f['title']} |\n"

    body += f"\n### POA&M Items\n\n"
    for item in poam_items:
        control = next((p["value"] for p in item.get("props", []) if p["name"] == "control-id"), "?")
        source = next((p["value"] for p in item.get("props", []) if p["name"] == "source"), "?")
        body += f"- **{control.upper()}** ({source}): {item['title']}\n"

    body += f"\n---\nGenerated by OSCAL Pipeline `enforce.py`\n"

    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    resp = requests.post(
        f"https://api.github.com/repos/{repo}/issues",
        headers=headers,
        json={"title": title, "body": body, "labels": ["pipeline", "compliance"]},
    )

    if resp.status_code == 201:
        issue_url = resp.json()["html_url"]
        print(f"    GitHub issue created: {issue_url}")
    else:
        print(f"    WARN: Could not create issue: {resp.status_code} {resp.text[:200]}")


def main():
    parser = argparse.ArgumentParser(description="Stage 5: Enforce — gate and alert on findings")
    parser.add_argument("--results", default="oscal/assessment-results.json", help="Assessment results")
    parser.add_argument("--poam", default="oscal/poam.json", help="POA&M file")
    parser.add_argument("--repo", default=None, help="GitHub repo (owner/name) for issue creation")
    parser.add_argument("--no-issue", action="store_true", help="Skip GitHub issue creation")
    args = parser.parse_args()

    print(f"\n{'='*62}")
    print(f"  OSCAL Pipeline — Stage 5: ENFORCE")
    print(f"  Gate and alert on findings")
    print(f"{'='*62}")

    # Load inputs
    print(f"\n  Loading assessment results: {args.results}")
    ar = load_oscal(args.results)
    counts = count_findings(ar)
    failed = get_failed_findings(ar)

    print(f"  Loading POA&M: {args.poam}")
    poam = load_oscal(args.poam)
    poam_items = poam.get("plan-of-action-and-milestones", {}).get("poam-items", [])

    # Determine pass/fail
    has_findings = len(poam_items) > 0

    print(f"\n{'='*62}")
    if has_findings:
        print(f"  RESULT: FAIL")
    else:
        print(f"  RESULT: PASS")
    print(f"{'='*62}")
    print(f"  Checks passed:     {counts.get('satisfied', 0)}")
    print(f"  Checks failed:     {counts.get('not-satisfied', 0)}")
    print(f"  POA&M items:       {len(poam_items)}")

    if failed:
        print(f"{'─'*62}")
        print(f"  Failed checks:")
        for f in failed:
            print(f"    ✗ [{f['control'].upper():8s}] [{f['source']:20s}] {f['title']}")

    if poam_items:
        print(f"{'─'*62}")
        print(f"  POA&M items:")
        for item in poam_items:
            control = next((p["value"] for p in item.get("props", []) if p["name"] == "control-id"), "?")
            source = next((p["value"] for p in item.get("props", []) if p["name"] == "source"), "?")
            print(f"    ✗ [{control.upper():8s}] [{source:20s}] {item['title']}")

    print(f"{'='*62}\n")

    # Create GitHub issue if failures exist
    if has_findings and not args.no_issue:
        print(f"  Creating GitHub issue...")
        create_github_issue(poam_items, failed, args.repo)

    sys.exit(1 if has_findings else 0)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Test import and --help**

Run: `cd /tmp/oscal-pipeline-workshop && python3 scripts/enforce.py --help`

Expected: Help text showing `--results`, `--poam`, `--repo`, `--no-issue`.

- [ ] **Step 3: Commit**

```bash
git add scripts/enforce.py
git commit -m "feat: add enforcement script (stage 5)

Reads assessment results and POA&M, prints pass/fail summary,
exits with code 1 if findings exist, and optionally opens a
GitHub issue with the finding details."
```

---

### Task 6: Pipeline runner

**Files:**
- Create: `scripts/run_pipeline.py`

Calls all 5 stages in sequence with clear stage banners.

- [ ] **Step 1: Create `scripts/run_pipeline.py`**

```python
"""
run_pipeline.py — End-to-end OSCAL pipeline runner

Calls all 5 stages in sequence:
  1. Convert SSP → OSCAL
  2. Discover inventory
  3. Assess controls
  4. Reconcile claims vs evidence
  5. Enforce (gate + alert)

USAGE:
  python run_pipeline.py
  python run_pipeline.py --skip-prowler --skip-trivy --no-issue
  python run_pipeline.py --help
"""

import argparse
import subprocess
import sys
import os
from datetime import datetime, timezone


def run_stage(stage_num: int, name: str, cmd: list) -> bool:
    """Run a pipeline stage and return True if it succeeded."""
    print(f"\n{'═'*62}")
    print(f"  Stage {stage_num}: {name}")
    print(f"{'═'*62}")

    result = subprocess.run(cmd, cwd=os.path.dirname(os.path.dirname(__file__)))

    if result.returncode != 0 and stage_num < 5:
        print(f"\n  ✗ Stage {stage_num} failed (exit code {result.returncode})")
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description="Run the full OSCAL pipeline end-to-end")
    parser.add_argument("--input", default="Templates/fedramp-moderate-template-ssp.xlsx",
                        help="SSP template input file")
    parser.add_argument("--output-dir", default="oscal", help="OSCAL output directory")
    parser.add_argument("--evidence-dir", default="evidence", help="Evidence directory")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--skip-prowler", action="store_true", help="Skip Prowler scan")
    parser.add_argument("--skip-trivy", action="store_true", help="Skip Trivy scan")
    parser.add_argument("--skip-nvd", action="store_true", help="Skip NVD lookup")
    parser.add_argument("--no-issue", action="store_true", help="Skip GitHub issue creation")
    parser.add_argument("--repo", default=None, help="GitHub repo for issue creation")
    args = parser.parse_args()

    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    python = sys.executable

    start_time = datetime.now(timezone.utc)

    print(f"\n{'═'*62}")
    print(f"  OSCAL COMPLIANCE PIPELINE")
    print(f"  Full end-to-end run")
    print(f"  Started: {start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'═'*62}")

    # Stage 1: Convert
    ok = run_stage(1, "CONVERT", [
        python, os.path.join(scripts_dir, "excel_to_oscal.py"),
        "--input", args.input,
        "--output", args.output_dir,
    ])
    if not ok:
        sys.exit(1)

    # Stage 2: Discover
    ok = run_stage(2, "DISCOVER", [
        python, os.path.join(scripts_dir, "discover.py"),
        "--ssp", os.path.join(args.output_dir, "ssp.json"),
        "--output", os.path.join(args.output_dir, "inventory.json"),
        "--region", args.region,
    ])
    if not ok:
        sys.exit(1)

    # Stage 3: Assess
    assess_cmd = [
        python, os.path.join(scripts_dir, "assess.py"),
        "--ssp", os.path.join(args.output_dir, "ssp.json"),
        "--output", os.path.join(args.output_dir, "assessment-results.json"),
        "--evidence", args.evidence_dir,
        "--region", args.region,
    ]
    if args.skip_prowler:
        assess_cmd.append("--skip-prowler")
    if args.skip_trivy:
        assess_cmd.append("--skip-trivy")
    if args.skip_nvd:
        assess_cmd.append("--skip-nvd")

    ok = run_stage(3, "ASSESS", assess_cmd)
    if not ok:
        sys.exit(1)

    # Stage 4: Reconcile
    ok = run_stage(4, "RECONCILE", [
        python, os.path.join(scripts_dir, "reconcile.py"),
        "--ssp", os.path.join(args.output_dir, "ssp.json"),
        "--results", os.path.join(args.output_dir, "assessment-results.json"),
        "--inventory", os.path.join(args.output_dir, "inventory.json"),
        "--output", os.path.join(args.output_dir, "poam.json"),
    ])
    if not ok:
        sys.exit(1)

    # Stage 5: Enforce
    enforce_cmd = [
        python, os.path.join(scripts_dir, "enforce.py"),
        "--results", os.path.join(args.output_dir, "assessment-results.json"),
        "--poam", os.path.join(args.output_dir, "poam.json"),
    ]
    if args.no_issue:
        enforce_cmd.append("--no-issue")
    if args.repo:
        enforce_cmd.extend(["--repo", args.repo])

    # Enforce may exit 1 (findings exist) — that's expected, not a pipeline failure
    run_stage(5, "ENFORCE", enforce_cmd)

    end_time = datetime.now(timezone.utc)
    elapsed = (end_time - start_time).total_seconds()

    print(f"\n{'═'*62}")
    print(f"  PIPELINE COMPLETE")
    print(f"  Duration: {elapsed:.1f}s")
    print(f"  Artifacts:")
    print(f"    {args.output_dir}/ssp.json")
    print(f"    {args.output_dir}/inventory.json")
    print(f"    {args.output_dir}/assessment-results.json")
    print(f"    {args.output_dir}/poam.json")
    print(f"    {args.evidence_dir}/screenshots/")
    print(f"{'═'*62}\n")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Test import and --help**

Run: `cd /tmp/oscal-pipeline-workshop && python3 scripts/run_pipeline.py --help`

Expected: Help text showing all stage-skip options and output paths.

- [ ] **Step 3: Commit**

```bash
git add scripts/run_pipeline.py
git commit -m "feat: add end-to-end pipeline runner

Calls all 5 stages in sequence with stage banners: convert,
discover, assess, reconcile, enforce. Supports skip flags
for optional tools and --no-issue for local runs."
```

---

### Task 7: GitHub Actions workflows

**Files:**
- Modify: `.github/workflows/oscal-validation.yml`
- Create: `.github/workflows/full-assessment.yml`

- [ ] **Step 1: Update `oscal-validation.yml` to add enforce gate**

Add enforce.py step after the existing validation steps. Read the current file first, then append:

```yaml
      - name: Run enforcement gate
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          pip install Pillow boto3 requests
          python scripts/enforce.py --results oscal-test/assessment-results.json --poam oscal-test/poam.json --no-issue
```

This step should be added after the existing "Validate SSP JSON structure" step.

- [ ] **Step 2: Create `.github/workflows/full-assessment.yml`**

```yaml
name: Full Pipeline Assessment

on:
  schedule:
    - cron: '0 6 * * 1'  # Weekly on Monday at 6am UTC
  workflow_dispatch:       # Manual trigger for live demo

jobs:
  assess:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install openpyxl python-docx boto3 requests Pillow

      - name: Stage 1 — Convert
        run: python scripts/excel_to_oscal.py --input Templates/fedramp-moderate-template-ssp.xlsx --output oscal

      - name: Stage 2 — Discover
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          AWS_DEFAULT_REGION: us-east-1
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_ORG: ${{ github.repository_owner }}
        run: python scripts/discover.py --ssp oscal/ssp.json --output oscal/inventory.json

      - name: Stage 3 — Assess
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          AWS_DEFAULT_REGION: us-east-1
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_ORG: ${{ github.repository_owner }}
        run: python scripts/assess.py --ssp oscal/ssp.json --output oscal/assessment-results.json --skip-prowler --skip-trivy

      - name: Stage 4 — Reconcile
        run: python scripts/reconcile.py --ssp oscal/ssp.json --results oscal/assessment-results.json --output oscal/poam.json

      - name: Stage 5 — Enforce
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: python scripts/enforce.py --results oscal/assessment-results.json --poam oscal/poam.json --repo ${{ github.repository }} || true

      - name: Commit updated artifacts
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add oscal/ evidence/ || true
          git diff --staged --quiet || git commit -m "chore: update assessment artifacts [pipeline run]"
          git push || true
```

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/oscal-validation.yml .github/workflows/full-assessment.yml
git commit -m "feat: add full assessment workflow and enforce gate

New full-assessment.yml runs weekly + on-demand via workflow_dispatch.
Extended oscal-validation.yml with enforce.py as CI gate step."
```

---

### Task 8: Dependencies and .gitignore updates

**Files:**
- Create: `requirements.txt`
- Modify: `.gitignore`

- [ ] **Step 1: Create `requirements.txt`**

```
openpyxl
python-docx
boto3
requests
Pillow
```

- [ ] **Step 2: Update `.gitignore` to include evidence artifacts but ignore sensitive files**

Add to `.gitignore`:

```
# Environment
.env

# Prowler output (large, regenerated)
evidence/prowler-output/

# Python
__pycache__/
*.pyc
```

- [ ] **Step 3: Create `evidence/.gitkeep`**

```bash
mkdir -p evidence/screenshots
touch evidence/.gitkeep
touch evidence/screenshots/.gitkeep
```

- [ ] **Step 4: Commit**

```bash
git add requirements.txt .gitignore evidence/.gitkeep evidence/screenshots/.gitkeep
git commit -m "chore: add requirements.txt, update .gitignore, scaffold evidence dirs"
```

---

### Task 9: Smoke test the full pipeline locally

This task verifies that all scripts load, parse args, and the pipeline runner connects them.

- [ ] **Step 1: Verify all scripts show --help without errors**

```bash
cd /tmp/oscal-pipeline-workshop
python3 scripts/discover.py --help
python3 scripts/assess.py --help
python3 scripts/reconcile.py --help
python3 scripts/enforce.py --help
python3 scripts/run_pipeline.py --help
```

Expected: Each shows its help text without import errors.

- [ ] **Step 2: Run converter to produce base artifacts**

```bash
python3 scripts/excel_to_oscal.py --input Templates/fedramp-moderate-template-ssp.xlsx --output oscal
```

Expected: 57 controls, CONVERSION COMPLETE.

- [ ] **Step 3: Test reconcile + enforce against skeleton (no assessment data yet)**

```bash
python3 scripts/reconcile.py --ssp oscal/ssp.json --results oscal/assessment-results.json --output oscal/poam.json
python3 scripts/enforce.py --results oscal/assessment-results.json --poam oscal/poam.json --no-issue
```

Expected: Reconcile should flag all implemented controls as "unverified" (no evidence yet). Enforce should exit 1 (findings exist) and print the POA&M items.

- [ ] **Step 4: Verify pipeline runner --help**

```bash
python3 scripts/run_pipeline.py --help
```

Expected: Shows all options for skipping tools and controlling output.

- [ ] **Step 5: Final commit with any fixes**

```bash
git add -A
git status
# If there are changes:
git commit -m "fix: address smoke test issues"
git push origin main
```
