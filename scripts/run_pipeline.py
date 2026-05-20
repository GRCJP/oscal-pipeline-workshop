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
    parser.add_argument("--skip-inspectors", action="store_true", help="Skip deep inspector checks")
    parser.add_argument("--no-issue", action="store_true", help="Skip GitHub issue creation")
    parser.add_argument("--repo", default=None, help="GitHub repo for issue creation")
    parser.add_argument("--github-repo", default=None, help="Scope GitHub checks to a single repo")
    parser.add_argument("--no-report", action="store_true", help="Skip HTML dashboard generation")
    parser.add_argument("--no-export-ssp", action="store_true", help="Skip updated SSP Excel export")
    parser.add_argument("--no-export-poam", action="store_true", help="Skip POA&M Excel export")
    parser.add_argument("--no-linear", action="store_true", help="Skip Linear issue export")
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
    discover_cmd = [
        python, os.path.join(scripts_dir, "discover.py"),
        "--ssp", os.path.join(args.output_dir, "ssp.json"),
        "--output", os.path.join(args.output_dir, "inventory.json"),
        "--region", args.region,
    ]
    if args.github_repo:
        discover_cmd.extend(["--github-repo", args.github_repo])
    ok = run_stage(2, "DISCOVER", discover_cmd)
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
    if args.skip_inspectors:
        assess_cmd.append("--skip-inspectors")
    if args.github_repo:
        assess_cmd.extend(["--github-repo", args.github_repo])

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

    # Stage 6: Report
    report_artifacts = []

    if not args.no_report:
        run_stage(6, "REPORT — HTML Dashboard", [
            python, os.path.join(scripts_dir, "report.py"),
            "--ssp", os.path.join(args.output_dir, "ssp.json"),
            "--results", os.path.join(args.output_dir, "assessment-results.json"),
            "--poam", os.path.join(args.output_dir, "poam.json"),
            "--inventory", os.path.join(args.output_dir, "inventory.json"),
            "--output", os.path.join(args.output_dir, "report.html"),
        ])
        report_artifacts.append(f"{args.output_dir}/report.html")

    if not args.no_export_ssp:
        run_stage(6, "REPORT — Updated SSP Export", [
            python, os.path.join(scripts_dir, "export_ssp.py"),
            "--ssp", os.path.join(args.output_dir, "ssp.json"),
            "--results", os.path.join(args.output_dir, "assessment-results.json"),
            "--template", args.input,
            "--output", os.path.join(args.output_dir, "updated-ssp.xlsx"),
        ])
        report_artifacts.append(f"{args.output_dir}/updated-ssp.xlsx")

    if not args.no_export_poam:
        run_stage(6, "REPORT — POA&M Export", [
            python, os.path.join(scripts_dir, "export_poam.py"),
            "--poam", os.path.join(args.output_dir, "poam.json"),
            "--output", os.path.join(args.output_dir, "poam-report.xlsx"),
        ])
        report_artifacts.append(f"{args.output_dir}/poam-report.xlsx")

    if not args.no_linear:
        run_stage(6, "REPORT — Linear POA&M Export", [
            python, os.path.join(scripts_dir, "export_to_linear.py"),
            "--poam", os.path.join(args.output_dir, "poam.json"),
            "--results", os.path.join(args.output_dir, "assessment-results.json"),
        ])

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
    for a in report_artifacts:
        print(f"    {a}")
    print(f"    {args.evidence_dir}/screenshots/")
    print(f"{'═'*62}\n")


if __name__ == "__main__":
    main()
