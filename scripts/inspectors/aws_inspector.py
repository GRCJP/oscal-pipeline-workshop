"""
aws_inspector.py — AWS Security Inspector

Deep compliance checks beyond what assess.py covers.
Based on the grclanker aws-sec-inspector spec.

USAGE:
  python scripts/inspectors/aws_inspector.py
  python scripts/inspectors/aws_inspector.py --region us-west-2
  python scripts/inspectors/aws_inspector.py --output evidence/custom-output.json
"""

import sys, os, json, argparse, csv, io
from datetime import datetime, timezone

import boto3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from pipeline_utils import stable_uuid, now_iso

BANNER = """
==============================================================
  AWS Security Inspector
  Deep compliance checks beyond basic assessment
==============================================================
"""


# ── Helpers ──────────────────────────────────────────────────────────────────

def make_finding(check_type, title, description, status, control_mappings,
                 resource=None, severity="medium"):
    """Build a finding dict."""
    f = {
        "type": check_type,
        "title": title,
        "description": description,
        "status": status,
        "control_mappings": {"fedramp": control_mappings},
        "severity": severity,
    }
    if resource:
        f["resource"] = resource
    return f


def safe_call(label, fn, *args, **kwargs):
    """Call an AWS API; return result or None on AccessDenied/other errors."""
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
        if code in ("AccessDeniedException", "AccessDenied",
                     "UnauthorizedAccess", "AuthorizationError"):
            print(f"    [WARN] {label}: access denied, skipping")
        else:
            print(f"    [WARN] {label}: {e}")
        return None


# ── Check: Root Account ──────────────────────────────────────────────────────

def check_root_account(iam) -> list:
    print("\n  [1/8] Root account access keys")
    findings = []
    summary = safe_call("get_account_summary", iam.get_account_summary)
    if summary is None:
        return findings

    keys_present = summary["SummaryMap"].get("AccountAccessKeysPresent", 0)
    if keys_present > 0:
        findings.append(make_finding(
            "root_account_usage",
            "Root account has access keys",
            "The root account has active access keys. Root access keys should be removed.",
            "fail",
            ["ac-6(1)"],
            severity="critical",
        ))
        print("    FAIL  Root account has access keys")
    else:
        findings.append(make_finding(
            "root_account_usage",
            "Root account has no access keys",
            "The root account does not have active access keys.",
            "pass",
            ["ac-6(1)"],
        ))
        print("    PASS  Root account has no access keys")
    return findings


# ── Check: Credential Report ────────────────────────────────────────────────

def check_credential_report(iam, account_id) -> list:
    print("\n  [2/8] Credential report analysis")
    findings = []

    # Generate report (may need retries)
    for _ in range(5):
        resp = safe_call("generate_credential_report",
                         iam.generate_credential_report)
        if resp is None:
            return findings
        if resp.get("State") == "COMPLETE":
            break
        import time
        time.sleep(2)

    report = safe_call("get_credential_report", iam.get_credential_report)
    if report is None:
        return findings

    content = report["Content"].decode("utf-8")
    reader = csv.DictReader(io.StringIO(content))
    now = datetime.now(timezone.utc)

    for row in reader:
        user = row.get("user", "<root_account>")
        arn = row.get("arn", f"arn:aws:iam::{account_id}:user/{user}")

        # Skip root account row for user-level checks
        if user == "<root_account>":
            continue

        # MFA check
        mfa = row.get("mfa_active", "false")
        if mfa.lower() != "true":
            findings.append(make_finding(
                "no_mfa",
                f"No MFA: {user}",
                f"IAM user '{user}' has no MFA device enabled.",
                "fail",
                ["ia-2", "ia-2(1)"],
                resource=arn,
                severity="high",
            ))
            print(f"    FAIL  No MFA: {user}")
        else:
            findings.append(make_finding(
                "no_mfa",
                f"MFA enabled: {user}",
                f"IAM user '{user}' has MFA enabled.",
                "pass",
                ["ia-2", "ia-2(1)"],
                resource=arn,
            ))
            print(f"    PASS  MFA enabled: {user}")

        # Password last used > 90 days
        pwd_last = row.get("password_last_used", "N/A")
        if pwd_last not in ("N/A", "no_information", "not_supported"):
            try:
                pwd_date = datetime.fromisoformat(
                    pwd_last.replace("Z", "+00:00").replace("+00:00", "+00:00")
                )
                if hasattr(pwd_date, 'tzinfo') and pwd_date.tzinfo is None:
                    pwd_date = pwd_date.replace(tzinfo=timezone.utc)
                days = (now - pwd_date).days
                if days > 90:
                    findings.append(make_finding(
                        "unused_credentials",
                        f"Stale password: {user}",
                        f"IAM user '{user}' password last used {days} days ago (>90).",
                        "fail",
                        ["ac-2"],
                        resource=arn,
                        severity="medium",
                    ))
                    print(f"    FAIL  Stale password: {user} ({days} days)")
            except (ValueError, TypeError):
                pass

        # Access key last used > 90 days
        for key_num in ("1", "2"):
            key_active = row.get(f"access_key_{key_num}_active", "false")
            if key_active.lower() != "true":
                continue
            key_last = row.get(f"access_key_{key_num}_last_used_date", "N/A")
            if key_last in ("N/A", "no_information", "not_supported"):
                continue
            try:
                key_date = datetime.fromisoformat(
                    key_last.replace("Z", "+00:00").replace("+00:00", "+00:00")
                )
                if hasattr(key_date, 'tzinfo') and key_date.tzinfo is None:
                    key_date = key_date.replace(tzinfo=timezone.utc)
                days = (now - key_date).days
                if days > 90:
                    findings.append(make_finding(
                        "stale_access_key",
                        f"Stale access key {key_num}: {user}",
                        f"IAM user '{user}' access key {key_num} last used {days} days ago (>90).",
                        "fail",
                        ["ia-5"],
                        resource=arn,
                        severity="medium",
                    ))
                    print(f"    FAIL  Stale access key {key_num}: {user} ({days} days)")
            except (ValueError, TypeError):
                pass

    if not any(f["type"] == "no_mfa" for f in findings):
        print("    (no IAM users found in credential report)")

    return findings


# ── Check: IAM Policy Analysis ──────────────────────────────────────────────

def check_iam_policies(iam) -> list:
    print("\n  [3/8] IAM policy analysis (least privilege)")
    findings = []

    resp = safe_call("get_account_authorization_details",
                     iam.get_account_authorization_details,
                     Filter=["LocalManagedPolicy"])
    if resp is None:
        return findings

    policies = resp.get("Policies", [])
    # Handle pagination
    while resp.get("IsTruncated"):
        resp = safe_call("get_account_authorization_details (cont)",
                         iam.get_account_authorization_details,
                         Filter=["LocalManagedPolicy"],
                         Marker=resp["Marker"])
        if resp is None:
            break
        policies.extend(resp.get("Policies", []))

    wildcard_count = 0
    for policy in policies:
        policy_name = policy.get("PolicyName", "unknown")
        arn = policy.get("Arn", "")
        for version in policy.get("PolicyVersionList", []):
            if not version.get("IsDefaultVersion"):
                continue
            doc = version.get("Document", {})
            # Document may be a string (URL-encoded) or dict
            if isinstance(doc, str):
                import urllib.parse
                doc = json.loads(urllib.parse.unquote(doc))
            statements = doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            for stmt in statements:
                if stmt.get("Effect") != "Allow":
                    continue
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]
                if "*" in actions and "*" in resources:
                    wildcard_count += 1
                    findings.append(make_finding(
                        "excessive_permissions",
                        f"Wildcard policy: {policy_name}",
                        f"Policy '{policy_name}' grants Action:* on Resource:*.",
                        "fail",
                        ["ac-6"],
                        resource=arn,
                        severity="high",
                    ))
                    print(f"    FAIL  Wildcard policy: {policy_name}")

    if wildcard_count == 0:
        findings.append(make_finding(
            "excessive_permissions",
            "No wildcard policies found",
            "No customer-managed policies grant Action:* on Resource:*.",
            "pass",
            ["ac-6"],
        ))
        print("    PASS  No wildcard policies found")

    return findings


# ── Check: Access Analyzer ───────────────────────────────────────────────────

def check_access_analyzer(session, region) -> list:
    print("\n  [4/8] IAM Access Analyzer")
    findings = []
    aa = session.client("accessanalyzer", region_name=region)

    resp = safe_call("list_analyzers", aa.list_analyzers)
    if resp is None:
        return findings

    analyzers = resp.get("analyzers", [])
    if not analyzers:
        findings.append(make_finding(
            "access_analyzer_no_findings",
            "No Access Analyzer configured",
            "IAM Access Analyzer is not enabled in this region.",
            "fail",
            ["ac-6"],
            severity="medium",
        ))
        print("    FAIL  No Access Analyzer configured")
        return findings

    findings.append(make_finding(
        "access_analyzer_no_findings",
        f"Access Analyzer active ({len(analyzers)} analyzer(s))",
        "IAM Access Analyzer is enabled.",
        "pass",
        ["ac-6"],
    ))
    print(f"    PASS  Access Analyzer active ({len(analyzers)} analyzer(s))")

    # Check for active findings
    for analyzer in analyzers:
        analyzer_arn = analyzer.get("arn", "")
        aa_findings = safe_call("list_findings",
                                aa.list_findings,
                                analyzerArn=analyzer_arn,
                                filter={"status": {"eq": ["ACTIVE"]}})
        if aa_findings is None:
            continue
        active = aa_findings.get("findings", [])
        for af in active[:10]:  # Cap at 10 to avoid noise
            findings.append(make_finding(
                "cross_account_access",
                f"Access Analyzer finding: {af.get('resourceType', 'unknown')}",
                f"External access to {af.get('resource', 'unknown')} "
                f"by {af.get('principal', {})}: {af.get('condition', {})}",
                "fail",
                ["ac-6"],
                resource=af.get("resource"),
                severity="high",
            ))
            print(f"    FAIL  External access: {af.get('resource', 'unknown')}")

    return findings


# ── Check: GuardDuty ─────────────────────────────────────────────────────────

def check_guardduty(session, region) -> list:
    print("\n  [5/8] GuardDuty")
    findings = []
    gd = session.client("guardduty", region_name=region)

    resp = safe_call("list_detectors", gd.list_detectors)
    if resp is None:
        return findings

    detectors = resp.get("DetectorIds", [])
    if not detectors:
        findings.append(make_finding(
            "guardduty_disabled",
            "GuardDuty not enabled",
            "Amazon GuardDuty is not enabled in this region.",
            "fail",
            ["si-4"],
            severity="high",
        ))
        print("    FAIL  GuardDuty not enabled")
        return findings

    findings.append(make_finding(
        "guardduty_disabled",
        "GuardDuty enabled",
        f"Amazon GuardDuty is enabled ({len(detectors)} detector(s)).",
        "pass",
        ["si-4"],
    ))
    print(f"    PASS  GuardDuty enabled ({len(detectors)} detector(s))")

    # Check for active findings
    for det_id in detectors:
        gd_findings = safe_call("list_findings",
                                gd.list_findings,
                                DetectorId=det_id,
                                FindingCriteria={
                                    "Criterion": {
                                        "service.archived": {
                                            "Eq": ["false"]
                                        }
                                    }
                                })
        if gd_findings is None:
            continue
        finding_ids = gd_findings.get("FindingIds", [])
        if finding_ids:
            # Get details for up to 10 findings
            details = safe_call("get_findings",
                                gd.get_findings,
                                DetectorId=det_id,
                                FindingIds=finding_ids[:10])
            if details:
                for gf in details.get("Findings", []):
                    findings.append(make_finding(
                        "guardduty_findings",
                        f"GuardDuty: {gf.get('Title', 'Unknown')}",
                        gf.get("Description", ""),
                        "fail",
                        ["si-4"],
                        resource=gf.get("Arn"),
                        severity=gf.get("Severity", 5) >= 7 and "high" or "medium",
                    ))
                    print(f"    FAIL  GuardDuty finding: {gf.get('Title', 'Unknown')}")
        else:
            print("    PASS  No active GuardDuty findings")

    return findings


# ── Check: Security Hub ──────────────────────────────────────────────────────

def check_security_hub(session, region) -> list:
    print("\n  [6/8] Security Hub")
    findings = []
    sh = session.client("securityhub", region_name=region)

    hub = safe_call("describe_hub", sh.describe_hub)
    if hub is None:
        findings.append(make_finding(
            "security_hub_disabled",
            "Security Hub not enabled",
            "AWS Security Hub is not enabled in this region.",
            "fail",
            ["si-4", "ra-5"],
            severity="high",
        ))
        print("    FAIL  Security Hub not enabled")
        return findings

    findings.append(make_finding(
        "security_hub_disabled",
        "Security Hub enabled",
        f"AWS Security Hub is enabled (subscribed {hub.get('SubscribedAt', 'unknown')}).",
        "pass",
        ["si-4", "ra-5"],
    ))
    print(f"    PASS  Security Hub enabled")

    # List active standards
    standards = safe_call("get_enabled_standards", sh.get_enabled_standards)
    if standards:
        for std in standards.get("StandardsSubscriptions", []):
            name = std.get("StandardsArn", "").split("/")[-1]
            status = std.get("StandardsStatus", "unknown")
            print(f"    INFO  Standard: {name} ({status})")

    return findings


# ── Check: S3 Account Public Access Block ────────────────────────────────────

def check_s3_public_access_block(session, account_id, region) -> list:
    print("\n  [7/8] S3 account-level public access block")
    findings = []
    s3ctrl = session.client("s3control", region_name=region)

    resp = safe_call("get_public_access_block",
                     s3ctrl.get_public_access_block,
                     AccountId=account_id)
    if resp is None:
        findings.append(make_finding(
            "s3_public_access",
            "No account-level S3 public access block",
            "Account-level S3 Block Public Access is not configured.",
            "fail",
            ["ac-3", "sc-7"],
            severity="high",
        ))
        print("    FAIL  No account-level S3 public access block")
        return findings

    config = resp.get("PublicAccessBlockConfiguration", {})
    all_blocked = all([
        config.get("BlockPublicAcls", False),
        config.get("IgnorePublicAcls", False),
        config.get("BlockPublicPolicy", False),
        config.get("RestrictPublicBuckets", False),
    ])

    if all_blocked:
        findings.append(make_finding(
            "s3_public_access",
            "S3 public access fully blocked at account level",
            "All four S3 Block Public Access settings are enabled at the account level.",
            "pass",
            ["ac-3", "sc-7"],
        ))
        print("    PASS  S3 public access fully blocked at account level")
    else:
        missing = [k for k in ("BlockPublicAcls", "IgnorePublicAcls",
                                "BlockPublicPolicy", "RestrictPublicBuckets")
                   if not config.get(k, False)]
        findings.append(make_finding(
            "s3_public_access",
            "S3 public access block incomplete",
            f"Account-level S3 Block Public Access missing: {', '.join(missing)}.",
            "fail",
            ["ac-3", "sc-7"],
            severity="medium",
        ))
        print(f"    FAIL  S3 public access block incomplete (missing: {', '.join(missing)})")

    return findings


# ── Check: CloudTrail Organization Trail ─────────────────────────────────────

def check_cloudtrail_org(session, region) -> list:
    print("\n  [8/8] CloudTrail organization trail")
    findings = []
    ct = session.client("cloudtrail", region_name=region)

    resp = safe_call("describe_trails", ct.describe_trails)
    if resp is None:
        return findings

    trails = resp.get("trailList", [])
    org_trails = [t for t in trails if t.get("IsOrganizationTrail", False)]

    if org_trails:
        for t in org_trails:
            findings.append(make_finding(
                "cloudtrail_not_org_trail",
                f"Organization trail: {t.get('Name', 'unknown')}",
                f"CloudTrail '{t.get('Name')}' is an organization trail.",
                "pass",
                ["au-2"],
                resource=t.get("TrailARN"),
            ))
            print(f"    PASS  Organization trail: {t.get('Name', 'unknown')}")
    else:
        trail_names = [t.get("Name", "unknown") for t in trails]
        findings.append(make_finding(
            "cloudtrail_not_org_trail",
            "No organization trail",
            f"No CloudTrail trails are organization trails. "
            f"Trails found: {', '.join(trail_names) if trail_names else 'none'}.",
            "fail",
            ["au-2"],
            severity="medium",
        ))
        if trails:
            print(f"    FAIL  No organization trail ({len(trails)} trail(s) found)")
        else:
            print("    FAIL  No CloudTrail trails found")

    return findings


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AWS Security Inspector -- deep AWS compliance checks"
    )
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", default="evidence/aws-inspector-findings.json")
    args = parser.parse_args()

    print(BANNER)

    session = boto3.Session(region_name=args.region)
    iam = session.client("iam", region_name=args.region)
    sts = session.client("sts", region_name=args.region)

    # Get account ID
    try:
        account_id = sts.get_caller_identity()["Account"]
    except Exception as e:
        print(f"  ERROR: Cannot get AWS identity: {e}")
        sys.exit(1)

    print(f"  Account:  {account_id}")
    print(f"  Region:   {args.region}")
    print(f"  Time:     {now_iso()}")

    all_findings = []

    # Run all checks
    all_findings.extend(check_root_account(iam))
    all_findings.extend(check_credential_report(iam, account_id))
    all_findings.extend(check_iam_policies(iam))
    all_findings.extend(check_access_analyzer(session, args.region))
    all_findings.extend(check_guardduty(session, args.region))
    all_findings.extend(check_security_hub(session, args.region))
    all_findings.extend(check_s3_public_access_block(session, account_id, args.region))
    all_findings.extend(check_cloudtrail_org(session, args.region))

    # Summary
    total = len(all_findings)
    passes = sum(1 for f in all_findings if f["status"] == "pass")
    fails = total - passes

    result = {
        "inspector": "aws-sec-inspector",
        "account_id": account_id,
        "region": args.region,
        "timestamp": now_iso(),
        "summary": {"total": total, "pass": passes, "fail": fails},
        "findings": all_findings,
    }

    # Write output
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\n  ────────────────────────────────────────────")
    print(f"  Results:  {total} checks | {passes} pass | {fails} fail")
    print(f"  Output:   {args.output}")
    print(f"  ────────────────────────────────────────────\n")


if __name__ == "__main__":
    main()
