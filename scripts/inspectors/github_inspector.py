"""
github_inspector.py — GitHub Security Inspector

Deep GitHub compliance checks beyond what assess.py covers.
Checks: org settings, outside collaborators, branch protection,
secret scanning, Dependabot, Actions permissions, webhook SSL.

USAGE:
  python github_inspector.py --org GRCJP --repo oscal-pipeline-workshop
  python github_inspector.py --help

REQUIRES:
  - requests
  - GITHUB_TOKEN in environment
"""

import sys
import os
import json
import argparse
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from pipeline_utils import stable_uuid, now_iso

BANNER = """
==============================================================
  GitHub Security Inspector
  Deep compliance checks beyond basic assessment
==============================================================
"""

API_BASE = "https://api.github.com"


def _headers(token: str) -> dict:
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }


def _get(url: str, token: str):
    """GET request with error handling. Returns (response, error_skipped)."""
    try:
        resp = requests.get(url, headers=_headers(token), timeout=30)
        if resp.status_code in (403, 404):
            print(f"    WARNING: {resp.status_code} for {url} — skipping")
            return resp, True
        resp.raise_for_status()
        return resp, False
    except requests.RequestException as e:
        print(f"    WARNING: Request failed for {url}: {e}")
        return None, True


def _finding(finding_type: str, title: str, description: str,
             status: str, controls: list, resource: str,
             severity: str = "medium") -> dict:
    return {
        "type": finding_type,
        "title": title,
        "description": description,
        "status": status,
        "control_mappings": {"fedramp": controls},
        "resource": resource,
        "severity": severity,
    }


# ── Check functions ─────────────────────────────────────────────────────────


def check_org_settings(org: str, token: str) -> list:
    """Check organization security settings."""
    print(f"\n  [Org Settings] Checking {org}...")
    findings = []
    resp, skipped = _get(f"{API_BASE}/orgs/{org}", token)
    if skipped or resp is None:
        print("    Skipped org settings check")
        return findings

    data = resp.json()

    # 2FA requirement
    if data.get("two_factor_requirement_enabled") is True:
        findings.append(_finding(
            "org_2fa_enabled",
            f"Org 2FA required: {org}",
            "Organization requires two-factor authentication for all members",
            "pass", ["ia-2"], org,
        ))
        print("    2FA required: pass")
    else:
        findings.append(_finding(
            "no_org_2fa",
            f"Org 2FA not required: {org}",
            "Organization does not require two-factor authentication for all members",
            "fail", ["ia-2"], org, "high",
        ))
        print("    2FA required: FAIL")

    # Default repository permission
    default_perm = data.get("default_repository_permission", "read")
    if default_perm in ("write", "admin"):
        findings.append(_finding(
            "broad_default_permissions",
            f"Broad default permissions: {org} ({default_perm})",
            f"Default repository permission is '{default_perm}' — should be 'read' or 'none'",
            "fail", ["ac-6"], org, "high",
        ))
        print(f"    Default permission '{default_perm}': FAIL")
    else:
        findings.append(_finding(
            "default_permissions_ok",
            f"Default permissions acceptable: {org} ({default_perm})",
            f"Default repository permission is '{default_perm}'",
            "pass", ["ac-6"], org,
        ))
        print(f"    Default permission '{default_perm}': pass")

    # Members can create repos
    if data.get("members_can_create_repositories") is True:
        findings.append(_finding(
            "unrestricted_repo_creation",
            f"Members can create repos: {org}",
            "Organization allows all members to create repositories",
            "fail", ["cm-3"], org, "medium",
        ))
        print("    Members can create repos: FAIL")
    else:
        findings.append(_finding(
            "repo_creation_restricted",
            f"Repo creation restricted: {org}",
            "Organization restricts repository creation",
            "pass", ["cm-3"], org,
        ))
        print("    Members can create repos: pass")

    return findings


def check_outside_collaborators(org: str, token: str) -> list:
    """Check for outside collaborators."""
    print(f"\n  [Outside Collaborators] Checking {org}...")
    findings = []
    resp, skipped = _get(f"{API_BASE}/orgs/{org}/outside_collaborators", token)
    if skipped or resp is None:
        print("    Skipped outside collaborators check")
        return findings

    collabs = resp.json()
    count = len(collabs)
    if count > 0:
        names = ", ".join(c["login"] for c in collabs[:5])
        suffix = f" (and {count - 5} more)" if count > 5 else ""
        findings.append(_finding(
            "outside_collaborators_exist",
            f"Outside collaborators found: {org} ({count})",
            f"Organization has {count} outside collaborator(s): {names}{suffix}",
            "fail", ["ac-2"], org, "medium",
        ))
        print(f"    Outside collaborators: {count} — FAIL")
    else:
        findings.append(_finding(
            "no_outside_collaborators",
            f"No outside collaborators: {org}",
            "Organization has no outside collaborators",
            "pass", ["ac-2"], org,
        ))
        print("    Outside collaborators: 0 — pass")

    return findings


def check_branch_protection(org: str, repo: str, token: str) -> list:
    """Check branch protection on default branch."""
    print(f"\n  [Branch Protection] Checking {org}/{repo}...")
    findings = []
    resource = f"{org}/{repo}"

    # Get default branch
    resp, skipped = _get(f"{API_BASE}/repos/{resource}", token)
    if skipped or resp is None:
        print("    Skipped branch protection check")
        return findings
    default_branch = resp.json().get("default_branch", "main")

    # Get branch protection
    resp, skipped = _get(
        f"{API_BASE}/repos/{resource}/branches/{default_branch}/protection",
        token,
    )
    if skipped or resp is None:
        findings.append(_finding(
            "branch_protection_disabled",
            f"No branch protection: {repo}/{default_branch}",
            "Repository has no branch protection rules on the default branch",
            "fail", ["cm-3"], resource, "high",
        ))
        print(f"    Protection on {default_branch}: FAIL (not configured)")
        return findings

    prot = resp.json()
    print(f"    Protection on {default_branch}: configured")

    # Required reviews
    pr_reviews = prot.get("required_pull_request_reviews")
    if pr_reviews:
        findings.append(_finding(
            "required_reviews_enabled",
            f"Required reviews enabled: {repo}/{default_branch}",
            "Pull request reviews are required before merging",
            "pass", ["cm-3", "sa-11"], resource,
        ))
        print("    Required reviews: pass")
    else:
        findings.append(_finding(
            "no_required_reviews",
            f"No required reviews: {repo}/{default_branch}",
            "Pull request reviews are not required before merging",
            "fail", ["cm-3", "sa-11"], resource, "high",
        ))
        print("    Required reviews: FAIL")

    # Status checks
    status_checks = prot.get("required_status_checks")
    if status_checks:
        findings.append(_finding(
            "status_checks_enabled",
            f"Status checks required: {repo}/{default_branch}",
            "Status checks are required before merging",
            "pass", ["sa-10"], resource,
        ))
        print("    Status checks: pass")
    else:
        findings.append(_finding(
            "no_status_checks",
            f"No status checks: {repo}/{default_branch}",
            "No status checks are required before merging",
            "fail", ["sa-10"], resource, "medium",
        ))
        print("    Status checks: FAIL")

    # Force pushes
    force_push = prot.get("allow_force_pushes", {})
    if isinstance(force_push, dict) and force_push.get("enabled"):
        findings.append(_finding(
            "force_push_allowed",
            f"Force push allowed: {repo}/{default_branch}",
            "Force pushes are allowed on the default branch",
            "fail", ["cm-3"], resource, "high",
        ))
        print("    Force push: FAIL (allowed)")
    else:
        findings.append(_finding(
            "force_push_blocked",
            f"Force push blocked: {repo}/{default_branch}",
            "Force pushes are blocked on the default branch",
            "pass", ["cm-3"], resource,
        ))
        print("    Force push: pass (blocked)")

    # Deletions
    deletions = prot.get("allow_deletions", {})
    if isinstance(deletions, dict) and deletions.get("enabled"):
        findings.append(_finding(
            "branch_deletion_allowed",
            f"Branch deletion allowed: {repo}/{default_branch}",
            "Branch deletion is allowed on the default branch",
            "fail", ["cm-3"], resource, "medium",
        ))
        print("    Branch deletion: FAIL (allowed)")
    else:
        findings.append(_finding(
            "branch_deletion_blocked",
            f"Branch deletion blocked: {repo}/{default_branch}",
            "Branch deletion is blocked on the default branch",
            "pass", ["cm-3"], resource,
        ))
        print("    Branch deletion: pass (blocked)")

    return findings


def check_secret_scanning(org: str, repo: str, token: str) -> list:
    """Check secret scanning alerts."""
    print(f"\n  [Secret Scanning] Checking {org}/{repo}...")
    findings = []
    resource = f"{org}/{repo}"

    resp, skipped = _get(
        f"{API_BASE}/repos/{resource}/secret-scanning/alerts?state=open&per_page=5",
        token,
    )
    if resp is not None and resp.status_code == 404:
        findings.append(_finding(
            "secret_scanning_disabled",
            f"Secret scanning not enabled: {repo}",
            "Secret scanning is not enabled for this repository",
            "fail", ["ia-5"], resource, "high",
        ))
        print("    Secret scanning: FAIL (not enabled)")
        return findings

    if skipped or resp is None:
        print("    Skipped secret scanning check")
        return findings

    alerts = resp.json()
    if len(alerts) > 0:
        findings.append(_finding(
            "open_secret_alerts",
            f"Open secret scanning alerts: {repo} ({len(alerts)}+)",
            f"Repository has {len(alerts)}+ open secret scanning alert(s)",
            "fail", ["ia-5"], resource, "critical",
        ))
        print(f"    Open secret alerts: {len(alerts)}+ — FAIL")
    else:
        findings.append(_finding(
            "no_open_secret_alerts",
            f"No open secret alerts: {repo}",
            "No open secret scanning alerts found",
            "pass", ["ia-5"], resource,
        ))
        print("    Open secret alerts: 0 — pass")

    return findings


def check_dependabot(org: str, repo: str, token: str) -> list:
    """Check Dependabot alerts."""
    print(f"\n  [Dependabot] Checking {org}/{repo}...")
    findings = []
    resource = f"{org}/{repo}"

    resp, skipped = _get(
        f"{API_BASE}/repos/{resource}/dependabot/alerts?state=open&per_page=5",
        token,
    )
    if resp is not None and resp.status_code == 404:
        findings.append(_finding(
            "dependabot_disabled",
            f"Dependabot not enabled: {repo}",
            "Dependabot alerts are not enabled for this repository",
            "fail", ["ra-5"], resource, "high",
        ))
        print("    Dependabot: FAIL (not enabled)")
        return findings

    if skipped or resp is None:
        print("    Skipped Dependabot check")
        return findings

    alerts = resp.json()
    if len(alerts) > 0:
        findings.append(_finding(
            "open_dependabot_alerts",
            f"Open Dependabot alerts: {repo} ({len(alerts)}+)",
            f"Repository has {len(alerts)}+ open Dependabot alert(s)",
            "fail", ["ra-5", "si-2"], resource, "high",
        ))
        print(f"    Open Dependabot alerts: {len(alerts)}+ — FAIL")
    else:
        findings.append(_finding(
            "no_open_dependabot_alerts",
            f"No open Dependabot alerts: {repo}",
            "No open Dependabot alerts found",
            "pass", ["ra-5", "si-2"], resource,
        ))
        print("    Open Dependabot alerts: 0 — pass")

    return findings


def check_actions_security(org: str, repo: str, token: str) -> list:
    """Check GitHub Actions permissions."""
    print(f"\n  [Actions Security] Checking {org}/{repo}...")
    findings = []
    resource = f"{org}/{repo}"

    resp, skipped = _get(
        f"{API_BASE}/repos/{resource}/actions/permissions", token,
    )
    if skipped or resp is None:
        print("    Skipped Actions security check")
        return findings

    data = resp.json()
    allowed = data.get("allowed_actions", "unknown")
    if allowed == "all":
        findings.append(_finding(
            "actions_unrestricted",
            f"All Actions allowed: {repo}",
            "Repository allows all GitHub Actions without restriction",
            "fail", ["cm-7"], resource, "medium",
        ))
        print(f"    Allowed actions '{allowed}': FAIL")
    else:
        findings.append(_finding(
            "actions_restricted",
            f"Actions restricted: {repo} ({allowed})",
            f"Repository restricts GitHub Actions to '{allowed}'",
            "pass", ["cm-7"], resource,
        ))
        print(f"    Allowed actions '{allowed}': pass")

    return findings


def check_webhooks(org: str, repo: str, token: str) -> list:
    """Check webhook SSL verification."""
    print(f"\n  [Webhooks] Checking {org}/{repo}...")
    findings = []
    resource = f"{org}/{repo}"

    resp, skipped = _get(f"{API_BASE}/repos/{resource}/hooks", token)
    if skipped or resp is None:
        print("    Skipped webhook check")
        return findings

    hooks = resp.json()
    if not hooks:
        print("    No webhooks configured")
        return findings

    insecure = [h for h in hooks
                if h.get("config", {}).get("insecure_ssl") == "1"]
    if insecure:
        findings.append(_finding(
            "webhook_no_ssl",
            f"Webhook(s) without SSL verification: {repo} ({len(insecure)})",
            f"{len(insecure)} webhook(s) have SSL verification disabled",
            "fail", ["sc-8"], resource, "high",
        ))
        print(f"    Insecure webhooks: {len(insecure)} — FAIL")
    else:
        findings.append(_finding(
            "webhooks_ssl_verified",
            f"All webhooks use SSL: {repo}",
            f"All {len(hooks)} webhook(s) have SSL verification enabled",
            "pass", ["sc-8"], resource,
        ))
        print(f"    All {len(hooks)} webhooks SSL verified: pass")

    return findings


# ── Main ────────────────────────────────────────────────────────────────────


def get_org_repos(org: str, token: str) -> list:
    """List all repos in the org (names only)."""
    repos = []
    page = 1
    while True:
        resp, skipped = _get(
            f"{API_BASE}/orgs/{org}/repos?per_page=100&page={page}", token,
        )
        if skipped or resp is None:
            break
        batch = resp.json()
        if not batch:
            break
        repos.extend(r["name"] for r in batch)
        page += 1
    return repos


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="GitHub Security Inspector — deep GitHub compliance checks",
    )
    parser.add_argument("--org", default=os.environ.get("GITHUB_ORG", ""))
    parser.add_argument("--repo", default=None,
                        help="Scope to single repo (e.g. oscal-pipeline-workshop)")
    parser.add_argument("--output",
                        default="evidence/github-inspector-findings.json")
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print("ERROR: GITHUB_TOKEN not set in environment")
        sys.exit(1)
    if not args.org:
        print("ERROR: --org required (or set GITHUB_ORG)")
        sys.exit(1)

    org = args.org
    print(f"  Org:  {org}")
    print(f"  Repo: {args.repo or '(all)'}")

    all_findings = []

    # Org-level checks
    all_findings.extend(check_org_settings(org, token))
    all_findings.extend(check_outside_collaborators(org, token))

    # Determine repos to check
    if args.repo:
        repos = [args.repo]
    else:
        repos = get_org_repos(org, token)
        print(f"\n  Found {len(repos)} repo(s) in {org}")

    # Per-repo checks
    for repo in repos:
        print(f"\n  ── Repo: {repo} ──")
        all_findings.extend(check_branch_protection(org, repo, token))
        all_findings.extend(check_secret_scanning(org, repo, token))
        all_findings.extend(check_dependabot(org, repo, token))
        all_findings.extend(check_actions_security(org, repo, token))
        all_findings.extend(check_webhooks(org, repo, token))

    # Summary
    total = len(all_findings)
    passes = sum(1 for f in all_findings if f["status"] == "pass")
    fails = total - passes

    result = {
        "inspector": "github-sec-inspector",
        "org": org,
        "repo": args.repo or "(all)",
        "timestamp": now_iso(),
        "summary": {"total": total, "pass": passes, "fail": fails},
        "findings": all_findings,
    }

    # Write output
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\n  ── Summary ──")
    print(f"    Total: {total}  |  Pass: {passes}  |  Fail: {fails}")
    print(f"    Output: {args.output}")
    print()


if __name__ == "__main__":
    main()
