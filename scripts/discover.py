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
