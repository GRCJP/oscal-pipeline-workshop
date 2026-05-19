# OSCAL Pipeline Workshop

A hands-on workshop that teaches the methodology behind continuous compliance — not just how to convert an SSP, but how to discover what's actually in your environment, test it against security controls, and maintain that cycle continuously.

## The Problem

Organizations don't know what they don't know. The SSP was written months ago. Since then, resources were spun up that nobody documented, tools were decommissioned that nobody removed, and controls claiming "we inventory all components" are already wrong. Traditional assessments rely on manual artifacts, screenshots, and waiting — and they only give you a point-in-time snapshot.

## The Method

This pipeline treats the SSP as a **hypothesis**, not a source of truth. It proves or disproves it:

1. **Convert** — Read the SSP and extract what it claims. The converter scans narratives for tool and service mentions. No assumptions about what should exist.
2. **Discover** — Query the actual environment (AWS, GitHub). Build a real inventory. Compare it against what the SSP claims. Flag drift: undocumented resources the SSP missed, and missing resources the SSP claims but don't exist.
3. **Assess** — Run security checks against what was discovered. Test IAM, S3, CloudTrail, security groups, VPC flow logs, KMS, GitHub branch protection, and more. Evidence method is determined by what the checks actually find, not predicted upfront.
4. **Reconcile** — Compare SSP claims against evidence. Controls are confirmed, contradicted, or unverified. Gaps become POA&M items. Undocumented resources become POA&M items.
5. **Enforce** — Gate and alert. The pipeline passes or fails. Findings create GitHub issues automatically.

Run this on a schedule and you have **continuous compliance** — not a quarterly exercise.

## OSCAL Model Alignment

| OSCAL Model | Pipeline Stage |
|---|---|
| Catalog (controls) | Referenced — NIST 800-53 Rev 5 |
| Profile (baseline) | Referenced — FedRAMP Moderate |
| Component Definition | Convert extracts SSP-claimed components. Discovery adds what's actually there. |
| System Security Plan | Convert — the claim |
| Assessment Results | Assess + Reconcile — the evidence and verdicts |
| POA&M | Reconcile — the action items |

## Repository Structure

```
scripts/
  excel_to_oscal.py         # Stage 1: Convert Excel SSP to OSCAL
  docx_to_oscal.py          # Stage 1: Convert Word SSP to OSCAL
  discover.py               # Stage 2: Discover AWS + GitHub inventory, drift detection
  assess.py                 # Stage 3: Run security checks, capture evidence
  reconcile.py              # Stage 4: Compare claims vs evidence, generate POA&M
  enforce.py                # Stage 5: Pass/fail gate, GitHub issue alerting
  run_pipeline.py           # End-to-end runner for all 5 stages
  pipeline_utils.py         # Shared helpers (keyword matching, screenshots, OSCAL builders)
  aws-setup.sh              # Provision demo AWS environment with intentional findings
  inspector_control_map.json # grclanker inspector finding to control mapping
  config.py                 # Intentional credential finding for scanners
Templates/                  # FedRAMP SSP templates (Excel & Word)
terraform/                  # Intentional IaC misconfigs for Trivy scanning
prereqs/                    # Setup checklist and .env.example
.github/workflows/          # CI: OSCAL validation, CodeQL, full assessment
```

## Tools Used

| Tool | Purpose | Cost |
|------|---------|------|
| Python 3 | Run pipeline scripts | Free |
| AWS CLI + Config | Asset discovery and inventory | Free tier |
| GitHub + Actions | Source control, CI/CD, code scanning | Free |
| Prowler | Cloud security posture scanning | Free (OSS) |
| Trivy | Container, IaC, and dependency scanning | Free (OSS) |
| CodeQL | Static application security testing | Free (on GitHub) |
| NVD API | Vulnerability intelligence | Free (public) |

The pipeline doesn't care which specific tools you use — it cares about what controls they prove. If your org uses Splunk instead of CloudWatch, or Okta instead of IAM, the pattern is the same.

## Getting Started

See [WORKSHOP-COMMANDS.md](WORKSHOP-COMMANDS.md) for the full command reference.

Quick start:

```bash
git clone https://github.com/GRCJP/oscal-pipeline-workshop.git
cd oscal-pipeline-workshop
pip3 install -r requirements.txt
cp prereqs/.env.example .env
# Edit .env with your AWS and GitHub credentials
export $(cat .env | grep -v '^#' | xargs)
```

Run the pipeline stage by stage, or all at once:

```bash
python3 scripts/run_pipeline.py --github-repo oscal-pipeline-workshop --skip-prowler --skip-trivy --no-issue
```

> **Important:** All AWS resources must be in **us-east-1**.

## Context

Tools like [Trestle](https://github.com/oscal-compass/compliance-trestle) and other OSCAL frameworks exist. This workshop helps you understand what's under the hood — the methodology, the process, and the thought behind what we're trying to streamline — so you can evaluate, extend, or build on those tools with confidence.

## Questions?

Reach out in the GRC Engineering Club channel.
