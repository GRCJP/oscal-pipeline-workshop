# OSCAL Pipeline Workshop

Hands-on workshop: build an OSCAL compliance pipeline with free, open-source tools. Convert FedRAMP SSPs to OSCAL, discover AWS assets, assess security posture, and reconcile findings into POA&M items.

## What You'll Build

A working compliance-as-code pipeline that:

1. **Converts** FedRAMP SSP templates (Excel or Word) into machine-readable OSCAL JSON
2. **Discovers** what resources actually exist in your AWS environment using AWS Config
3. **Assesses** security posture with Prowler, Trivy, CodeQL, and NVD vulnerability data
4. **Reconciles** evidence against SSP claims — anything that doesn't match becomes a POA&M item

The pipeline infers each control's evidence method automatically: if two or more tools in the registry can verify a control, it's **automated**; one tool means **hybrid** (tool evidence plus human review); no tools means **manual**; inherited stays inherited.

## Why This Approach

Stop treating the SSP as a source of truth — treat it as a hypothesis. The pipeline proves or disproves it. Your SSP was written months ago; since then, resources were spun up that nobody documented. Controls claiming "we inventory all components" may already be wrong.

**Discovery before assessment.** You can't assess what you haven't discovered. AWS Config gives you the ground truth — every resource in your account. That's your real inventory, not the spreadsheet someone updated last quarter.

## Repository Structure

```
├── Templates/                  # FedRAMP SSP templates (Excel & Word)
├── scripts/
│   ├── excel_to_oscal.py       # Convert Excel SSP → OSCAL JSON
│   ├── docx_to_oscal.py        # Convert Word SSP → OSCAL JSON
│   ├── aws-setup.sh            # Provision demo AWS environment
│   ├── assessment-results.json # Assessment results artifact
│   └── poam.json               # POA&M artifact
├── prereqs/
│   ├── setup-checklist.md      # Step-by-step setup guide
│   └── .env.example            # Environment variable template
├── .github/workflows/
│   ├── oscal-validation.yml    # CI: validate OSCAL output on push
│   └── codeql.yml              # SAST scanning via CodeQL
└── Instructions - Club SOP/    # Session facilitation guide
```

## Tools Used

| Tool | Purpose | Cost |
|------|---------|------|
| Python 3 | Run converter scripts | Free |
| AWS CLI + Config | Asset discovery and inventory | Free tier |
| GitHub + Actions | Source control and CI/CD pipeline | Free |
| Prowler | Cloud security posture scanning | Free (OSS) |
| Trivy | Container, IaC, and dependency scanning | Free (OSS) |
| CodeQL | Static application security testing | Free (on GitHub) |
| NVD API | Vulnerability intelligence | Free (public) |

## Getting Started

1. **Clone** this repository
2. **Follow** the [setup checklist](prereqs/setup-checklist.md) (allow 30-45 minutes)
3. **Run** the converter to verify your setup:
   ```bash
   python3 scripts/excel_to_oscal.py \
     --input Templates/fedramp-moderate-template-ssp.xlsx \
     --output oscal
   ```
   You should see **57 controls** processed and **CONVERSION COMPLETE**.

> **Important:** All AWS resources must be in **us-east-1**. The pipeline won't see resources in other regions.

## Customization

- **Tool registry:** The converter includes a registry of 8 tools. If your org uses different tools (e.g., Splunk, Azure AD), add them to the registry — describe the tool and what it proves.
- **SSP format:** The converters auto-detect control table layouts. For non-standard formats, describe your document structure and adjust the parsing logic.
- **Config section:** The configuration block at the top of each converter is the only part that changes between organizations.

## Context

Tools like [Trestle](https://github.com/oscal-compass/compliance-trestle) and other OSCAL frameworks exist. This workshop helps you understand what's under the hood so you can evaluate, extend, or build on those tools with confidence.

## Questions?

Reach out in the GRC Engineering Club channel.
