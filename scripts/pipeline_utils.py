"""
pipeline_utils.py — Shared constants and helpers for the OSCAL pipeline.

Every pipeline script imports from here instead of duplicating
OSCAL_NAMESPACE, stable_uuid, TOOL_REGISTRY, and screenshot capture.
"""

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ── UUID v5 deterministic identifiers ─────────────────────────────────────────
OSCAL_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

def stable_uuid(name: str) -> str:
    return str(uuid.uuid5(OSCAL_NAMESPACE, name))

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def now_filesafe() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")


# ── Tool Registry ─────────────────────────────────────────────────────────────
# Mirrors excel_to_oscal.py TOOL_REGISTRY. Single source of truth for the pipeline.

TOOL_REGISTRY = {
    "aws_iam": {
        "title": "AWS IAM",
        "type": "service",
        "families": ["ac", "ia"],
        "controls": ["ac-2", "ac-2(1)", "ac-3", "ac-5", "ac-6", "ac-6(1)", "ac-7",
                      "ia-2", "ia-2(1)", "ia-4", "ia-5", "ia-5(1)"],
        "evidence_type": "Cloud Identity & Access",
    },
    "aws_s3": {
        "title": "AWS S3 & KMS",
        "type": "service",
        "families": ["sc", "cp", "au"],
        "controls": ["sc-28", "sc-7", "sc-8", "sc-12", "sc-13", "cp-9", "au-9"],
        "evidence_type": "Data Encryption, Storage & Backup",
    },
    "aws_cloudtrail": {
        "title": "AWS CloudTrail",
        "type": "service",
        "families": ["au"],
        "controls": ["au-2", "au-3", "au-12"],
        "evidence_type": "Audit Logging",
    },
    "aws_config": {
        "title": "AWS Config",
        "type": "service",
        "families": ["cm", "pm", "ra"],
        "controls": ["cm-2", "cm-3", "cm-8", "ra-5", "sa-10"],
        "evidence_type": "Asset Discovery & Configuration Inventory",
    },
    "github": {
        "title": "GitHub",
        "type": "software",
        "families": ["ac", "cm", "sa"],
        "controls": ["ac-2", "ac-3", "ac-5", "ac-6", "cm-2", "cm-3", "cm-5", "cm-7", "cm-8", "sa-10"],
        "evidence_type": "Source Control & Change Management",
    },
    "github_actions": {
        "title": "GitHub Actions",
        "type": "software",
        "families": ["sa", "cm", "si"],
        "controls": ["sa-10", "sa-11", "cm-3", "si-2"],
        "evidence_type": "CI/CD Pipeline Security",
    },
    "codeql": {
        "title": "CodeQL (GitHub SAST)",
        "type": "software",
        "families": ["sa", "si"],
        "controls": ["sa-11", "si-2", "ra-5"],
        "evidence_type": "Static Application Security Testing",
    },
    "trivy": {
        "title": "Trivy (Open Source Scanner)",
        "type": "software",
        "families": ["ra", "si", "cm"],
        "controls": ["ra-5", "si-2", "cm-6", "cm-7"],
        "evidence_type": "Container, IaC & Dependency Scanning",
    },
    "nvd": {
        "title": "NIST NVD / OSV.dev",
        "type": "service",
        "families": ["ra", "si"],
        "controls": ["ra-5", "si-2"],
        "evidence_type": "Vulnerability Intelligence",
    },
    "prowler": {
        "title": "Prowler (Open Source CSPM)",
        "type": "software",
        "families": ["ac", "au", "cm", "ia", "ra", "sc", "si"],
        "controls": ["ac-2", "ac-3", "ac-6", "ac-7", "au-2", "au-9", "cm-6", "cm-7",
                      "ia-2", "ia-5", "ra-5", "sc-7", "sc-28", "si-4"],
        "evidence_type": "Cloud Security Posture Management",
    },
}


def get_tools_for_control(control_id: str) -> list:
    """Return tool keys whose control list includes this control."""
    tools = []
    for key, tool in TOOL_REGISTRY.items():
        if control_id in tool["controls"]:
            tools.append(key)
    return tools


# ── Screenshot capture ────────────────────────────────────────────────────────

def capture_screenshot(text: str, output_path: str) -> str:
    """
    Render CLI text output to a PNG image using Pillow.
    Returns the path to the saved PNG.
    """
    from PIL import Image, ImageDraw, ImageFont

    lines = text.split("\n")
    # Use a monospace font — Pillow's default, or Courier if available
    try:
        font = ImageFont.truetype("Courier", 14)
    except (OSError, IOError):
        try:
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 14)
        except (OSError, IOError):
            font = ImageFont.load_default()

    # Calculate image size
    char_width = 8
    line_height = 18
    padding = 20
    max_line_len = max((len(line) for line in lines), default=40)
    img_width = max(max_line_len * char_width + padding * 2, 400)
    img_height = len(lines) * line_height + padding * 2

    # Dark background, light text — looks like a terminal
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
