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
import shutil
import subprocess
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
    capture_screenshot,
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


# ── Local tools we look for on the system ──────────────────────────────────

LOCAL_TOOLS = [
    {"command": "prowler",   "key": "prowler",       "title": "Prowler",        "type": "security-scanner"},
    {"command": "trivy",     "key": "trivy",          "title": "Trivy",          "type": "security-scanner"},
    {"command": "terraform", "key": "terraform",      "title": "Terraform",      "type": "iac"},
    {"command": "kubectl",   "key": "kubernetes",     "title": "Kubernetes",     "type": "orchestration"},
    {"command": "docker",    "key": "docker",         "title": "Docker",         "type": "container-runtime"},
    {"command": "gcloud",    "key": "gcp",            "title": "Google Cloud",   "type": "cloud-provider"},
    {"command": "az",        "key": "azure",          "title": "Microsoft Azure","type": "cloud-provider"},
    {"command": "linear",    "key": "linear",         "title": "Linear",         "type": "project-management"},
]


def discover_local_tools() -> list:
    """Scan the local environment for installed compliance-relevant tools."""
    print("\n    Scanning local environment for installed tools...")
    resources = []

    for tool in LOCAL_TOOLS:
        path = shutil.which(tool["command"])
        if path:
            # Try to get version
            version = "unknown"
            try:
                result = subprocess.run(
                    [tool["command"], "--version"],
                    capture_output=True, text=True, timeout=5,
                )
                out = (result.stdout or result.stderr).strip().split("\n")[0]
                if out:
                    version = out
            except Exception:
                pass

            resources.append({
                "type": f"Local::{tool['type']}",
                "id": f"local:{tool['command']}",
                "name": tool["title"],
                "source": "local_environment",
                "component_key": tool["key"],
                "details": {"path": path, "version": version},
            })
            print(f"      Local::{tool['type']:30s} {tool['title']} ({version})")
        else:
            print(f"      Local::{tool['type']:30s} {tool['title']} — not found")

    print(f"\n    Local tools discovered: {len(resources)}")
    return resources


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

    # Direct API checks for services AWS Config doesn't track
    print("\n    Checking additional AWS services...")

    try:
        kms = boto3.client("kms", region_name=region)
        keys = kms.list_keys(Limit=100).get("Keys", [])
        if keys:
            for k in keys:
                desc = kms.describe_key(KeyId=k["KeyId"]).get("KeyMetadata", {})
                if desc.get("KeyManager") == "CUSTOMER":
                    resources.append({
                        "type": "AWS::KMS::Key",
                        "id": k["KeyId"],
                        "name": f"KMS Key ({k['KeyId'][:8]}...)",
                        "source": "aws_kms",
                    })
                    print(f"      AWS::KMS::Key                              {k['KeyId'][:8]}... ✓")
    except Exception as e:
        print(f"      WARN: Could not check KMS: {e}")

    try:
        cw = boto3.client("cloudwatch", region_name=region)
        alarms = cw.describe_alarms(MaxRecords=1).get("MetricAlarms", [])
        if alarms:
            resources.append({
                "type": "AWS::CloudWatch::Alarm",
                "id": "cloudwatch-active",
                "name": "AWS CloudWatch",
                "source": "aws_cloudwatch",
            })
            print(f"      AWS::CloudWatch::Alarm                     active ✓")
    except Exception as e:
        print(f"      WARN: Could not check CloudWatch: {e}")

    try:
        ec2 = boto3.client("ec2", region_name=region)
        flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])
        if flow_logs:
            for fl in flow_logs:
                resources.append({
                    "type": "AWS::EC2::FlowLog",
                    "id": fl.get("FlowLogId", ""),
                    "name": f"VPC Flow Log ({fl.get('FlowLogId', '')})",
                    "source": "aws_ec2",
                })
                print(f"      AWS::EC2::FlowLog                          {fl.get('FlowLogId', '')} ✓")
        else:
            print(f"      AWS::EC2::FlowLog                          none found")
    except Exception as e:
        print(f"      WARN: Could not check VPC Flow Logs: {e}")

    print(f"\n    AWS resources discovered: {len(resources)}")
    return resources


def discover_github(github_repo: str = None) -> list:
    """Query GitHub API for repos, branch protection, workflows."""
    token = os.environ.get("GITHUB_TOKEN")
    org = os.environ.get("GITHUB_ORG")

    if not token or not org:
        print("    WARN: GITHUB_TOKEN or GITHUB_ORG not set — skipping GitHub discovery")
        return []

    import requests
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    resources = []

    # Scope to a single repo or scan all
    if github_repo:
        # Single repo mode — e.g. "oscal-pipeline-workshop"
        full_name = f"{org}/{github_repo}" if "/" not in github_repo else github_repo
        print(f"\n    Querying GitHub repo: {full_name}...")
        resp = requests.get(f"https://api.github.com/repos/{full_name}", headers=headers)
        if resp.status_code == 200:
            repos = [resp.json()]
        else:
            print(f"      WARN: Could not fetch repo {full_name}: {resp.status_code}")
            return []
    else:
        print(f"\n    Querying GitHub for org/user: {org}...")
        resp = requests.get(f"https://api.github.com/users/{org}/repos?per_page=100", headers=headers)
        if resp.status_code != 200:
            resp = requests.get(f"https://api.github.com/orgs/{org}/repos?per_page=100", headers=headers)
        if resp.status_code != 200:
            print(f"      WARN: Could not list repos: {resp.status_code}")
            return []
        repos = resp.json()

    if repos:
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


def extract_ssp_components(ssp: dict) -> dict:
    """Extract components declared in the SSP, grouped by origin."""
    components = {}
    sys_impl = ssp.get("system-security-plan", {}).get("system-implementation", {})
    for comp in sys_impl.get("components", []):
        if comp.get("type") == "this-system":
            continue
        title = comp.get("title", "")
        origin = "unknown"
        key = title.lower()
        for p in comp.get("props", []):
            if p["name"] == "origin":
                origin = p["value"]
            if p["name"] == "component-key":
                key = p["value"]
        components[key] = {
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
    discovered_services = set()
    for r in discovered:
        # Local tools and extended checks carry their own component_key
        if "component_key" in r:
            discovered_services.add(r["component_key"])
            continue

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
        elif "FlowLog" in rtype:
            discovered_services.add("vpc flow logs")
        elif "CloudWatch" in rtype:
            discovered_services.add("aws cloudwatch")
        elif "EC2" in rtype:
            discovered_services.add("aws ec2")
        elif "Repository" in rtype:
            discovered_services.add("github")
        elif "ActionsWorkflow" in rtype:
            discovered_services.add("github actions")
        elif "BranchProtection" in rtype:
            discovered_services.add("github")

    ssp_keys = set(ssp_components.keys())

    documented = []
    undocumented = []
    missing = []

    for svc in sorted(discovered_services):
        if svc in ssp_keys:
            documented.append(svc)
        else:
            undocumented.append(svc)

    for key in sorted(ssp_keys):
        if key not in discovered_services:
            missing.append(key)

    return {
        "total_discovered": len(discovered),
        "discovered_services": sorted(discovered_services),
        "ssp_components": len(ssp_components),
        "documented": documented,
        "undocumented": undocumented,
        "missing": missing,
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
                "documented": drift["documented"],
                "undocumented": drift["undocumented"],
                "missing": drift["missing"],
            },
        }
    }


def main():
    parser = argparse.ArgumentParser(description="Stage 2: Discover AWS + GitHub inventory")
    parser.add_argument("--ssp", default="oscal/ssp.json", help="Path to SSP JSON")
    parser.add_argument("--output", default="oscal/inventory.json", help="Output inventory path")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--screenshots", default="evidence/screenshots", help="Screenshot output dir")
    parser.add_argument("--github-repo", default=None, help="Scope to a single GitHub repo (e.g. oscal-pipeline-workshop)")
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
    github_resources = discover_github(args.github_repo)
    local_resources = discover_local_tools()
    all_resources = aws_resources + github_resources + local_resources

    # Capture discovery output as screenshot
    discovery_text = f"DISCOVERY RESULTS\n{'='*50}\n"
    discovery_text += f"AWS resources:    {len(aws_resources)}\n"
    discovery_text += f"GitHub resources: {len(github_resources)}\n"
    discovery_text += f"Local tools:      {len(local_resources)}\n"
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
    print(f"    Local tools:         {len(local_resources)}")
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


if __name__ == "__main__":
    main()
