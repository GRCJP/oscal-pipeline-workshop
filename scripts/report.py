#!/usr/bin/env python3
"""
report.py — Generate an HTML executive dashboard from OSCAL pipeline outputs.

Reads SSP, assessment-results, POA&M, and inventory JSON files and produces
a standalone report.html with inline CSS.  No JavaScript, no external deps.
"""

import argparse
import html
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
from pipeline_utils import load_oscal


# ── HTML template pieces ────────────────────────────────────────────────────

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    background: #1a1a2e;
    color: #e0e0e0;
    font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', 'Consolas', monospace;
    line-height: 1.6;
    padding: 2rem 1rem;
}
.container { max-width: 1100px; margin: 0 auto; }
h1 { font-size: 1.6rem; margin-bottom: 0.25rem; color: #ffffff; }
h2 { font-size: 1.2rem; margin: 2rem 0 1rem; color: #e0e0e0; border-bottom: 1px solid #0f3460; padding-bottom: 0.4rem; }
h3 { font-size: 1rem; margin-bottom: 0.5rem; }
.subtitle { color: #9e9e9e; font-size: 0.85rem; margin-bottom: 1.5rem; }
.card {
    background: #16213e;
    border: 1px solid #0f3460;
    border-radius: 8px;
    padding: 1.2rem;
    margin-bottom: 1.2rem;
}
/* Verdict boxes */
.verdict-row { display: flex; gap: 0.8rem; flex-wrap: wrap; margin-bottom: 1rem; }
.verdict-box {
    flex: 1;
    min-width: 120px;
    text-align: center;
    padding: 0.8rem 0.5rem;
    border-radius: 6px;
    font-weight: bold;
}
.verdict-box .count { font-size: 2rem; display: block; }
.verdict-box .label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; }
.vb-confirmed   { background: rgba(76,175,80,0.15);  border: 2px solid #4caf50; color: #4caf50; }
.vb-contradicted { background: rgba(244,67,54,0.15); border: 2px solid #f44336; color: #f44336; }
.vb-manual-review { background: rgba(255,152,0,0.15); border: 2px solid #ff9800; color: #ff9800; }
.vb-inherited   { background: rgba(158,158,158,0.15); border: 2px solid #9e9e9e; color: #9e9e9e; }
.vb-undocumented { background: rgba(255,87,34,0.15); border: 2px solid #ff5722; color: #ff5722; }
/* Stats row */
.stats-row { display: flex; gap: 1rem; flex-wrap: wrap; }
.stat { font-size: 0.85rem; }
.stat strong { color: #ffffff; }
/* Drift columns */
.drift-grid { display: flex; gap: 1rem; flex-wrap: wrap; }
.drift-col {
    flex: 1;
    min-width: 200px;
    background: #16213e;
    border-radius: 8px;
    padding: 1rem;
}
.drift-col h3 { margin-bottom: 0.5rem; }
.drift-col.documented  { border: 2px solid #4caf50; }
.drift-col.undocumented { border: 2px solid #f44336; }
.drift-col.missing     { border: 2px solid #ff9800; }
.drift-col ul { list-style: none; padding: 0; }
.drift-col li { padding: 0.2rem 0; font-size: 0.85rem; }
/* Tables */
table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
th {
    background: #0f3460;
    color: #ffffff;
    text-align: left;
    padding: 0.6rem 0.8rem;
}
td { padding: 0.5rem 0.8rem; border-bottom: 1px solid #0f3460; }
tr:nth-child(even) td { background: rgba(15,52,96,0.3); }
tr:nth-child(odd)  td { background: rgba(22,33,62,0.6); }
.row-fail td { background: rgba(244,67,54,0.12) !important; }
.empty-msg { color: #9e9e9e; font-style: italic; padding: 1rem 0; }
"""


def esc(text: str) -> str:
    """HTML-escape a string."""
    return html.escape(str(text)) if text else ""


def get_prop(props: list, name: str) -> str:
    """Return the first matching prop value, or ''."""
    for p in props:
        if p.get("name") == name:
            return p.get("value", "")
    return ""


def count_verdicts(observations: list) -> dict:
    """Count reconciliation verdicts across observations."""
    counts = {
        "confirmed": 0,
        "contradicted": 0,
        "manual-review": 0,
        "inherited": 0,
        "undocumented": 0,
    }
    seen = set()
    for obs in observations:
        obs_uuid = obs.get("uuid", "")
        for p in obs.get("props", []):
            if p.get("name") == "reconciliation-verdict":
                key = p["value"]
                # Avoid double-counting duplicate props on the same observation
                tag = (obs_uuid, key)
                if tag not in seen:
                    seen.add(tag)
                    if key in counts:
                        counts[key] += 1
                break  # only take the first verdict prop per observation
    return counts


def build_html(ssp_path, results_path, poam_path, inventory_path) -> str:
    ssp = load_oscal(ssp_path)
    results = load_oscal(results_path)
    poam = load_oscal(poam_path)
    inventory = load_oscal(inventory_path)

    # ── Extract data ──────────────────────────────────────────────────
    ssp_root = ssp.get("system-security-plan", {})
    system_name = ssp_root.get("system-characteristics", {}).get("system-name", "Unknown System")
    last_modified = ssp_root.get("metadata", {}).get("last-modified", "")

    ar_results = results.get("assessment-results", {}).get("results", [{}])[0]
    observations = ar_results.get("observations", [])
    findings = ar_results.get("findings", [])

    poam_items = poam.get("plan-of-action-and-milestones", {}).get("poam-items", [])
    drift = inventory.get("inventory", {}).get("drift-summary", {})

    # Verdicts
    verdicts = count_verdicts(observations)

    # Checks totals
    total_checks = len(findings)
    passed = sum(1 for f in findings if f.get("target", {}).get("status", {}).get("state") == "satisfied")
    failed = total_checks - passed

    # Failed findings for table
    failed_findings = [f for f in findings if f.get("target", {}).get("status", {}).get("state") == "not-satisfied"]

    # ── Build HTML ────────────────────────────────────────────────────
    parts = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append("<title>OSCAL Pipeline — Executive Dashboard</title>")
    parts.append(f"<style>{CSS}</style>")
    parts.append("</head><body>")
    parts.append('<div class="container">')

    # ── 1. Executive Summary ──────────────────────────────────────────
    parts.append("<h1>OSCAL Pipeline — Executive Dashboard</h1>")
    parts.append(f'<p class="subtitle">{esc(system_name)} &mdash; FedRAMP Moderate &mdash; {esc(last_modified)}</p>')
    parts.append('<div class="card">')

    # Verdict boxes
    parts.append('<div class="verdict-row">')
    verdict_cfg = [
        ("confirmed",    "vb-confirmed",    "Confirmed"),
        ("contradicted", "vb-contradicted",  "Contradicted"),
        ("manual-review","vb-manual-review", "Manual Review"),
        ("inherited",    "vb-inherited",     "Inherited"),
        ("undocumented", "vb-undocumented",  "Undocumented"),
    ]
    for key, css_class, label in verdict_cfg:
        parts.append(f'<div class="verdict-box {css_class}">')
        parts.append(f'<span class="count">{verdicts[key]}</span>')
        parts.append(f'<span class="label">{label}</span>')
        parts.append("</div>")
    parts.append("</div>")

    # Stats row
    parts.append('<div class="stats-row">')
    parts.append(f'<div class="stat"><strong>{total_checks}</strong> total checks</div>')
    parts.append(f'<div class="stat"><strong>{passed}</strong> passed</div>')
    parts.append(f'<div class="stat"><strong>{failed}</strong> failed</div>')
    parts.append(f'<div class="stat"><strong>{len(poam_items)}</strong> POA&amp;M items</div>')
    parts.append("</div>")
    parts.append("</div>")  # card

    # ── 2. Drift Detection ────────────────────────────────────────────
    parts.append("<h2>Drift Detection</h2>")
    parts.append('<div class="drift-grid">')

    drift_cols = [
        ("documented",   "Documented",   "#4caf50"),
        ("undocumented", "Undocumented", "#f44336"),
        ("missing",      "Missing",      "#ff9800"),
    ]
    for key, title, _color in drift_cols:
        items = drift.get(key, [])
        parts.append(f'<div class="drift-col {key}">')
        parts.append(f"<h3>{title} ({len(items)})</h3>")
        if items:
            parts.append("<ul>")
            for item in items:
                parts.append(f"<li>{esc(item)}</li>")
            parts.append("</ul>")
        else:
            parts.append('<p class="empty-msg">None</p>')
        parts.append("</div>")

    parts.append("</div>")  # drift-grid

    # ── 3. Failed Checks ──────────────────────────────────────────────
    parts.append("<h2>Failed Checks</h2>")
    parts.append('<div class="card">')
    if failed_findings:
        parts.append("<table><thead><tr><th>Control</th><th>Source</th><th>Finding</th></tr></thead><tbody>")
        for f in failed_findings:
            ctrl = esc(f.get("target", {}).get("target-id", ""))
            source = esc(get_prop(f.get("props", []), "source"))
            desc = esc(f.get("description", ""))
            parts.append(f'<tr class="row-fail"><td>{ctrl}</td><td>{source}</td><td>{desc}</td></tr>')
        parts.append("</tbody></table>")
    else:
        parts.append('<p class="empty-msg">No failed checks — all controls satisfied.</p>')
    parts.append("</div>")

    # ── 4. POA&M Items ────────────────────────────────────────────────
    parts.append("<h2>POA&amp;M Items</h2>")
    parts.append('<div class="card">')
    if poam_items:
        parts.append("<table><thead><tr><th>Control ID</th><th>Finding</th><th>Source</th><th>Description</th></tr></thead><tbody>")
        for item in poam_items:
            props = item.get("props", [])
            ctrl = esc(get_prop(props, "control-id"))
            source = esc(get_prop(props, "source"))
            title = esc(item.get("title", ""))
            desc = esc(item.get("description", ""))
            parts.append(f"<tr><td>{ctrl}</td><td>{title}</td><td>{source}</td><td>{desc}</td></tr>")
        parts.append("</tbody></table>")
    else:
        parts.append('<p class="empty-msg">No open POA&amp;M items.</p>')
    parts.append("</div>")

    # Footer
    from datetime import timezone
    parts.append(f'<p class="subtitle" style="margin-top:2rem;text-align:center;">Generated {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")} UTC</p>')
    parts.append("</div></body></html>")

    return "\n".join(parts)


def main():
    parser = argparse.ArgumentParser(description="Generate HTML executive dashboard")
    parser.add_argument("--ssp", default="oscal/ssp.json")
    parser.add_argument("--results", default="oscal/assessment-results.json")
    parser.add_argument("--poam", default="oscal/poam.json")
    parser.add_argument("--inventory", default="oscal/inventory.json")
    parser.add_argument("--output", default="oscal/report.html")
    args = parser.parse_args()

    html_content = build_html(args.ssp, args.results, args.poam, args.inventory)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"    Dashboard written: {args.output}")


if __name__ == "__main__":
    main()
