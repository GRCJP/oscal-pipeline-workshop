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
    capture_screenshot, make_poam_item, oscal_roles_and_parties,
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
            verdict = "manual-review"
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

    # Deduplicate by title — inspector and basic checks may flag the same issue
    seen_titles = set()
    deduped = []
    for item in poam_items:
        if item["title"] not in seen_titles:
            seen_titles.add(item["title"])
            deduped.append(item)

    return deduped


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
                **oscal_roles_and_parties(),
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
        symbol = {"confirmed": "✓", "contradicted": "✗", "manual-review": "⚠",
                  "inherited": "→", "planned": "◯", "undocumented": "✗"}.get(v, " ")
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
        symbol = {"confirmed": "✓", "contradicted": "✗", "manual-review": "⚠",
                  "inherited": "→", "planned": "◯", "undocumented": "✗"}.get(v, " ")
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
