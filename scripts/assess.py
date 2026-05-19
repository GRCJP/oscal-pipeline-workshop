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
