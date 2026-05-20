"""
validate.py — OSCAL Schema Validation

Validates pipeline artifacts against official NIST OSCAL JSON schemas.
Supports two modes:
  1. Python (default) — uses jsonschema library against NIST schema files
  2. oscal-cli — uses NIST's Java-based CLI tool if installed

USAGE:
  python validate.py --dir oscal/
  python validate.py --dir oscal/ --use-cli
  python validate.py --help
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
from pipeline_utils import now_iso

# NIST OSCAL JSON schema URLs (v1.1.2)
OSCAL_SCHEMA_BASE = "https://github.com/usnistgov/OSCAL/releases/download/v1.1.2"
SCHEMAS = {
    "ssp.json": {
        "url": f"{OSCAL_SCHEMA_BASE}/oscal_ssp_schema.json",
        "root_key": "system-security-plan",
        "name": "System Security Plan",
    },
    "assessment-results.json": {
        "url": f"{OSCAL_SCHEMA_BASE}/oscal_assessment-results_schema.json",
        "root_key": "assessment-results",
        "name": "Assessment Results",
    },
    "poam.json": {
        "url": f"{OSCAL_SCHEMA_BASE}/oscal_poam_schema.json",
        "root_key": "plan-of-action-and-milestones",
        "name": "Plan of Action and Milestones",
    },
    "component-definition.json": {
        "url": f"{OSCAL_SCHEMA_BASE}/oscal_component_schema.json",
        "root_key": "component-definition",
        "name": "Component Definition",
    },
}

CACHE_DIR = os.path.join(os.path.dirname(__file__), ".schema-cache")


def fetch_schema(url: str) -> dict:
    """Download and cache an OSCAL JSON schema."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache_file = os.path.join(CACHE_DIR, os.path.basename(url))

    if os.path.exists(cache_file):
        with open(cache_file) as f:
            return json.load(f)

    print(f"    Downloading schema: {os.path.basename(url)}")
    try:
        import requests
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except ImportError:
        import ssl
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
        req = urllib.request.Request(url, headers={"User-Agent": "oscal-pipeline-workshop"})
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            data = json.loads(resp.read())
    with open(cache_file, "w") as f:
        json.dump(data, f)
    return data


def validate_python(artifact_path: str, schema_info: dict) -> tuple:
    """Validate using jsonschema library. Returns (passed, errors)."""
    try:
        import jsonschema
    except ImportError:
        return False, ["jsonschema not installed. Run: pip install jsonschema"]

    with open(artifact_path) as f:
        doc = json.load(f)

    # Check root key
    if schema_info["root_key"] not in doc:
        return False, [f"Missing root key: '{schema_info['root_key']}'"]

    try:
        schema = fetch_schema(schema_info["url"])
    except Exception as e:
        return False, [f"Could not fetch schema: {e}"]

    # OSCAL schemas use \p{} Unicode regex patterns that Python's re module
    # doesn't support. We skip pattern validation and focus on structure.
    def no_pattern_validator(validator_class):
        return jsonschema.validators.extend(validator_class, {"pattern": lambda *a, **k: ()})

    ValidatorClass = no_pattern_validator(jsonschema.Draft7Validator)
    validator = ValidatorClass(schema)
    errors = []
    for error in sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path)):
        path = ".".join(str(p) for p in error.absolute_path) or "(root)"
        errors.append(f"  {path}: {error.message[:120]}")

    return len(errors) == 0, errors


def validate_cli(artifact_path: str, schema_info: dict) -> tuple:
    """Validate using oscal-cli. Returns (passed, errors)."""
    model_type = schema_info["root_key"]
    try:
        result = subprocess.run(
            ["oscal-cli", "validate", artifact_path, "--as", model_type],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return True, []
        errors = [line.strip() for line in result.stderr.splitlines() if line.strip()]
        return False, errors or [result.stdout.strip()]
    except FileNotFoundError:
        return False, ["oscal-cli not found. Install from: https://github.com/usnistgov/oscal-cli"]
    except subprocess.TimeoutExpired:
        return False, ["oscal-cli timed out"]


def structural_check(artifact_path: str, schema_info: dict) -> list:
    """Quick structural checks beyond schema — OSCAL best practices."""
    warnings = []
    with open(artifact_path) as f:
        doc = json.load(f)

    root = doc.get(schema_info["root_key"], {})
    meta = root.get("metadata", {})

    if "roles" not in meta:
        warnings.append("  Missing metadata.roles (required by OSCAL)")
    if "parties" not in meta:
        warnings.append("  Missing metadata.parties (required by OSCAL)")
    if "last-modified" not in meta:
        warnings.append("  Missing metadata.last-modified")
    if "oscal-version" not in meta:
        warnings.append("  Missing metadata.oscal-version")

    # SSP-specific
    if schema_info["root_key"] == "system-security-plan":
        si = root.get("system-implementation", {})
        if "inventory-items" not in si:
            warnings.append("  SSP missing system-implementation.inventory-items")
        if "components" not in si:
            warnings.append("  SSP missing system-implementation.components")

    # AR-specific
    if schema_info["root_key"] == "assessment-results":
        results = root.get("results", [])
        if results and "end" not in results[0]:
            warnings.append("  Assessment result missing 'end' timestamp")

    # POA&M-specific
    if schema_info["root_key"] == "plan-of-action-and-milestones":
        items = root.get("poam-items", [])
        no_origins = sum(1 for i in items if "origins" not in i)
        if no_origins > 0:
            warnings.append(f"  {no_origins} POA&M items missing 'origins'")

    return warnings


def build_submission(oscal_dir: str, output_dir: str):
    """Package OSCAL artifacts into a submission bundle."""
    os.makedirs(output_dir, exist_ok=True)

    artifacts = []
    for filename in SCHEMAS:
        src = os.path.join(oscal_dir, filename)
        if os.path.exists(src):
            dst = os.path.join(output_dir, filename)
            with open(src) as f:
                doc = json.load(f)
            with open(dst, "w") as f:
                json.dump(doc, f, indent=2)
            artifacts.append(filename)

    # Build manifest
    manifest = {
        "title": "OSCAL Submission Package",
        "created": now_iso(),
        "producer": "GRC Engineering Club — OSCAL Pipeline Workshop",
        "oscal-version": "1.1.2",
        "artifacts": [],
    }
    for filename in artifacts:
        info = SCHEMAS[filename]
        filepath = os.path.join(output_dir, filename)
        size = os.path.getsize(filepath)
        manifest["artifacts"].append({
            "filename": filename,
            "model": info["name"],
            "root-key": info["root_key"],
            "size-bytes": size,
        })

    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    return artifacts, manifest_path


def main():
    parser = argparse.ArgumentParser(description="Validate OSCAL artifacts against official schemas")
    parser.add_argument("--dir", default="oscal", help="Directory containing OSCAL artifacts")
    parser.add_argument("--use-cli", action="store_true", help="Use oscal-cli instead of Python jsonschema")
    parser.add_argument("--submission", default=None, help="Build submission package to this directory")
    args = parser.parse_args()

    print(f"\n{'='*62}")
    print(f"  OSCAL Pipeline — Validation")
    mode = "oscal-cli" if args.use_cli else "Python jsonschema"
    print(f"  Mode: {mode}")
    print(f"{'='*62}")

    validate_fn = validate_cli if args.use_cli else validate_python

    total = 0
    passed = 0
    failed = 0

    for filename, schema_info in SCHEMAS.items():
        filepath = os.path.join(args.dir, filename)
        if not os.path.exists(filepath):
            continue

        total += 1
        print(f"\n  Validating: {schema_info['name']} ({filename})")

        ok, errors = validate_fn(filepath, schema_info)
        warnings = structural_check(filepath, schema_info)

        if ok:
            passed += 1
            print(f"    ✓ Schema valid")
        else:
            failed += 1
            print(f"    ✗ Schema errors: {len(errors)}")
            for e in errors[:10]:
                print(f"      {e}")
            if len(errors) > 10:
                print(f"      ... and {len(errors) - 10} more")

        if warnings:
            print(f"    ⚠ Structural warnings: {len(warnings)}")
            for w in warnings:
                print(f"      {w}")

    print(f"\n{'='*62}")
    print(f"  VALIDATION COMPLETE")
    print(f"{'='*62}")
    print(f"  Artifacts checked:  {total}")
    print(f"  Passed:             {passed}")
    print(f"  Failed:             {failed}")

    # Submission package
    if args.submission:
        print(f"\n{'='*62}")
        print(f"  Building Submission Package")
        print(f"{'='*62}")

        artifacts, manifest_path = build_submission(args.dir, args.submission)
        print(f"\n  Package: {args.submission}/")
        for a in artifacts:
            print(f"    {a}")
        print(f"    manifest.json")
        print(f"\n  This is what you hand to your assessor.")
        print(f"{'='*62}")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
