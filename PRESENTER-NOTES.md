# Presenter Notes — OSCAL Pipeline Workshop

Not for participants. This is your run-of-show and troubleshooting guide.

## The Message

This workshop is NOT about:
- Converting SSPs to a new file format
- Learning specific tools (Prowler, Trivy, etc.)
- Writing Python code

This workshop IS about:
- The methodology: discover what's there, test it, reconcile against claims, maintain the cycle
- Leveraging JSON as the assessment backbone — machine-readable, diffable, automatable
- The thought process: how to think about continuous compliance
- Using AI as a force multiplier: Claude is the working session, the scripts are the product

## Known Issues & Failure Modes

### AWS

| Issue | Symptom | Fix |
|---|---|---|
| Wrong region | 0 resources discovered | Check region selector in AWS Console — must be us-east-1 |
| Config not enabled | S3 buckets / resources missing from discovery | Run `bash scripts/aws-setup.sh` with admin credentials |
| svc-pipeline can't create resources | AccessDenied on setup | Setup script needs admin creds, not svc-pipeline. Use CloudShell |
| Credentials not loaded | `NoCredentialsError` | Run `export $(cat .env \| grep -v '^#' \| xargs)` |
| Buckets in wrong region | S3 shows in list but not in Config | Recreate in us-east-1 via aws-setup.sh |

### GitHub

| Issue | Symptom | Fix |
|---|---|---|
| Token wrong type | `gh auth token` gives `gho_` token that may lack scopes | Create a PAT (classic) with `repo` + `read:org` scopes |
| Token not in env | "GITHUB_TOKEN not set — skipping" | Add to .env, re-export |
| Org endpoint 404 | "Could not list repos" | GITHUB_ORG may be a user, not org — both work but API endpoint differs. Script handles this. |
| Rate limiting | 403 responses | Wait 60 seconds or use authenticated token |

### Python / Dependencies

| Issue | Symptom | Fix |
|---|---|---|
| Python < 3.10 | Syntax errors | `python3 --version` — need 3.10+ |
| Pillow fails on Linux | `pip install Pillow` errors | `sudo apt install libjpeg-dev zlib1g-dev` first |
| Module not found | `ModuleNotFoundError` | `pip3 install -r requirements.txt` |
| Windows .env loading | `export` doesn't exist | Use the PowerShell command in WORKSHOP-COMMANDS.md |

### Prowler

| Issue | Symptom | Fix |
|---|---|---|
| Not on PATH | "Prowler not found" | Script also tries `python3 -m prowler` — install with `pip3 install prowler` |
| Version mismatch | JSON parse errors | We parse v3.x format. v5 may differ. Use `--skip-prowler` if issues |
| Slow | Takes minutes | Normal — it checks many controls. Use `--skip-prowler` for demo speed |

### Linear

| Issue | Symptom | Fix |
|---|---|---|
| No API key | "LINEAR_API_KEY not set — skipping" | Create key in Linear Settings > API |
| Wrong team key | "Team not found" | Check LINEAR_TEAM_KEY matches the team key in Linear URL |
| Duplicate issues | Same finding appears twice | Fixed — reconcile deduplicates by title |

## Demo Flow

### Setup (before audience arrives)
```bash
cd oscal-pipeline-workshop
export $(cat .env | grep -v '^#' | xargs)
rm -rf oscal/ evidence/screenshots/*.png
```

### Stage 1: Convert
```bash
python3 scripts/excel_to_oscal.py --input Templates/fedramp-moderate-template-ssp.xlsx --output oscal
```
**Talk about:** SSP is the hypothesis. 57 controls all say "implemented." 9 components extracted from narratives, 51 controls mention no tools. Show AC-2 in the JSON — AWS IAM is "claimed" from the narrative.

**Stopping point:** Open oscal/ssp.json, show what a control looks like. The by-component says "claimed" — not proven. That's the point.

### Stage 2: Discover
```bash
python3 scripts/discover.py --ssp oscal/ssp.json --output oscal/inventory.json --github-repo oscal-pipeline-workshop
```
**Talk about:** "You can't assess what you haven't discovered." The SSP says 9 components. The environment has more. Drift detection shows 4 documented, 4 undocumented (blind spots), 5 missing (stale claims).

**Key question to pose:** "Your SSP claims CloudWatch and VPC Flow Logs. Discovery didn't find them. Are they really there, or is the SSP lying?"

### Stage 3: Assess
```bash
python3 scripts/assess.py --ssp oscal/ssp.json --github-repo oscal-pipeline-workshop --skip-prowler --skip-nvd
```
**Talk about:** Now we test. Not with screenshots and manual checks — with API calls. Every finding has a source, a control, and a status. The evidence method is determined by what actually ran, not predicted upfront.

**Key moment:** The failed checks list. "demo-no-mfa has no MFA. The SSP says IA-2 is implemented. The evidence says otherwise."

### Stage 4: Reconcile
```bash
python3 scripts/reconcile.py --ssp oscal/ssp.json --results oscal/assessment-results.json --inventory oscal/inventory.json --output oscal/poam.json
```
**Talk about:** This is where the SSP hypothesis gets tested. 4 confirmed, 9 contradicted, 41 manual-review, 3 inherited, 4 undocumented. Every contradiction becomes a POA&M item. Every undocumented resource becomes a POA&M item.

**Key line:** "4 out of 57 controls are confirmed by evidence. That's 7%. The other 93% are either contradicted, need manual review, or have blind spots."

### Stage 5: Enforce
```bash
python3 scripts/enforce.py --results oscal/assessment-results.json --poam oscal/poam.json --no-issue
```
**Talk about:** Gate and alert. Exit code 1 = fail. In CI, this blocks the merge. On a schedule, this opens an issue. The pipeline has teeth.

### Stage 6: Report
```bash
open oscal/report.html
```
**Talk about:** Executive summary anyone can read. No JSON knowledge needed. This is what you hand to leadership.

### Show Linear
```bash
python3 scripts/export_to_linear.py
```
**Talk about:** Findings become tracked work items. This is the lifecycle — discover, assess, remediate, verify. Run the pipeline again after fixes, POA&M items close automatically.

### Full Pipeline
```bash
python3 scripts/run_pipeline.py --github-repo oscal-pipeline-workshop --skip-prowler --skip-nvd --no-issue
```
**Talk about:** Everything we just did, one command. 12 seconds. This runs on a schedule. That's continuous compliance.

## Questions You'll Get

**"Is OSCAL just converting the SSP?"**
No. The conversion is step 1. The method is discover, assess, reconcile, enforce. OSCAL is the machine-readable backbone that makes automation possible.

**"Why not just use Prowler/Trivy/etc. directly?"**
Those tools produce findings. OSCAL maps them to controls. The pipeline reconciles findings against what the SSP claims. Individual tools tell you what's wrong — the pipeline tells you what that means for your compliance posture.

**"Do I need to know Python?"**
No. I built this with AI. The scripts are the product. You describe what you want, AI writes the code. The skill is knowing what to ask for.

**"Why skip the Assessment Plan?"**
The code IS the plan. The scripts define what's checked and how. Every run executes the same assessment. You don't need a separate PDF.

**"How does this work with FedRAMP/CMMC/SOC2?"**
Same method, different profile. The converter points to FedRAMP Moderate baseline. Change the profile reference and the control set changes. The pipeline doesn't care which framework — it cares about controls and evidence.

**"What about controls that can't be automated?"**
41 controls show "manual-review." Those need human attestation — training records, policy documents, physical security. The pipeline flags them so you know which ones need manual work. It doesn't pretend everything can be automated.
