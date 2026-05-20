"""
pipeline_utils.py — Shared constants and helpers for the OSCAL pipeline.

Every pipeline script imports from here instead of duplicating
OSCAL_NAMESPACE, stable_uuid, and screenshot capture.
"""

import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Load .env from project root so all pipeline scripts pick up credentials
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:
    pass

# ── UUID v5 deterministic identifiers ─────────────────────────────────────────
OSCAL_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

def stable_uuid(name: str) -> str:
    return str(uuid.uuid5(OSCAL_NAMESPACE, name))

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def now_filesafe() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")


# ── Known Components (name recognition only) ─────────────────────────────────
# This is NOT a registry. It does NOT map tools to controls or define what
# they prove. It just recognizes tool/service names in SSP narratives so the
# converter can say "the SSP mentions this tool for this control."
#
# Discovery finds what's actually in the environment — that's the real inventory.

KNOWN_COMPONENTS = {
    "aws iam":          {"title": "AWS IAM",          "type": "service"},
    "aws s3":           {"title": "AWS S3",           "type": "service"},
    "aws kms":          {"title": "AWS KMS",          "type": "service"},
    "aws cloudtrail":   {"title": "AWS CloudTrail",   "type": "service"},
    "aws config":       {"title": "AWS Config",       "type": "service"},
    "aws cloudwatch":   {"title": "AWS CloudWatch",   "type": "service"},
    "vpc flow logs":    {"title": "VPC Flow Logs",    "type": "service"},
    "github":           {"title": "GitHub",           "type": "software"},
    "github actions":   {"title": "GitHub Actions",   "type": "software"},
    "codeql":           {"title": "CodeQL",           "type": "software"},
    "trivy":            {"title": "Trivy",            "type": "software"},
    "prowler":          {"title": "Prowler",          "type": "software"},
    "jenkins":          {"title": "Jenkins",          "type": "software"},
    "splunk":           {"title": "Splunk",           "type": "software"},
    "okta":             {"title": "Okta",             "type": "service"},
    "azure ad":         {"title": "Azure AD",         "type": "service"},
    "duo":              {"title": "Duo",              "type": "service"},
}

# Sort by key length descending so "github actions" matches before "github"
_SORTED_KEYS = sorted(KNOWN_COMPONENTS.keys(), key=len, reverse=True)


def extract_components_from_text(text: str) -> list:
    """
    Scan text for mentions of known tools/services.
    Returns list of component keys found (e.g., ["aws iam", "github"]).
    Name recognition only — no control mapping.
    """
    if not text:
        return []
    lower = text.lower()
    found = []
    for key in _SORTED_KEYS:
        if key in lower:
            found.append(key)
            # Remove matched text to avoid "github actions" also matching "github"
            lower = lower.replace(key, "")
    return found


# ── Screenshot capture ────────────────────────────────────────────────────────

def capture_screenshot(text: str, output_path: str) -> str:
    """
    Render CLI text output to a PNG image using Pillow.
    Returns the path to the saved PNG.
    """
    from PIL import Image, ImageDraw, ImageFont

    lines = text.split("\n")
    try:
        font = ImageFont.truetype("Courier", 14)
    except (OSError, IOError):
        try:
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 14)
        except (OSError, IOError):
            font = ImageFont.load_default()

    char_width = 8
    line_height = 18
    padding = 20
    max_line_len = max((len(line) for line in lines), default=40)
    img_width = max(max_line_len * char_width + padding * 2, 400)
    img_height = len(lines) * line_height + padding * 2

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
