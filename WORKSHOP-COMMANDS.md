# Workshop Commands

Run all commands from the repository root.

## Setup (before the session)

```bash
git clone https://github.com/GRCJP/oscal-pipeline-workshop.git
cd oscal-pipeline-workshop
pip3 install -r requirements.txt
```

Copy and configure your environment:

```bash
cp prereqs/.env.example .env
```

Edit `.env` and fill in your credentials (no quotes, no spaces around `=`):

```
AWS_ACCESS_KEY_ID=your_key_here
AWS_SECRET_ACCESS_KEY=your_secret_here
AWS_DEFAULT_REGION=us-east-1
GITHUB_TOKEN=ghp_your_token_here
GITHUB_ORG=GRCJP
```

Load the environment:

```bash
# macOS / Linux
export $(cat .env | grep -v '^#' | xargs)

# Windows PowerShell
Get-Content .env | Where-Object { $_ -notmatch '^#' -and $_ -match '=' } | ForEach-Object { $k,$v = $_ -split '=',2; [System.Environment]::SetEnvironmentVariable($k,$v,'Process') }
```

Verify:

```bash
aws sts get-caller-identity
python3 --version
```

## Stage 1: Convert

The SSP becomes machine-readable OSCAL. This is the claim — what the SSP says is true.

```bash
python3 scripts/excel_to_oscal.py --input Templates/fedramp-moderate-template-ssp.xlsx --output oscal
```

Expected: 57 controls processed, CONVERSION COMPLETE.

## Stage 2: Discover

Find out what's actually in your environment. You can't assess what you haven't discovered.

```bash
python3 scripts/discover.py --ssp oscal/ssp.json --output oscal/inventory.json --github-repo oscal-pipeline-workshop
```

Expected: AWS resources (IAM users, S3 buckets, CloudTrail, Config) and GitHub resources (repo, workflows, branch protection status).

## Stage 3: Assess

Run checks against the live environment. Test the SSP's claims with real evidence.

```bash
python3 scripts/assess.py --ssp oscal/ssp.json --github-repo oscal-pipeline-workshop --skip-prowler --skip-trivy --skip-nvd
```

Expected: Pass/fail results for IAM (MFA, access keys), S3 (encryption, public access), CloudTrail (multi-region, log validation), and GitHub (branch protection, code scanning).

## Stage 4: Reconcile

Compare what the SSP claims vs what the evidence shows. Gaps become POA&M items.

```bash
python3 scripts/reconcile.py --ssp oscal/ssp.json --results oscal/assessment-results.json --output oscal/poam.json
```

Expected: Controls marked as confirmed, contradicted, or unverified. POA&M items generated for every contradiction and gap.

## Stage 5: Enforce

Gate and alert. Does the system pass or fail?

```bash
python3 scripts/enforce.py --results oscal/assessment-results.json --poam oscal/poam.json --no-issue
```

Expected: FAIL with a list of POA&M items and exit code 1.

## Full Pipeline (end-to-end)

After walking through each stage individually, run the full pipeline to see it all together:

```bash
python3 scripts/run_pipeline.py --github-repo oscal-pipeline-workshop --skip-prowler --skip-trivy --no-issue
```

## Troubleshooting

**`ModuleNotFoundError: No module named 'openpyxl'`**
Run `pip3 install -r requirements.txt` again.

**`ModuleNotFoundError: No module named 'PIL'`**
Pillow needs system libraries on Linux: `sudo apt install libjpeg-dev zlib1g-dev` then `pip3 install Pillow`.

**`botocore.exceptions.NoCredentialsError`**
Your AWS credentials aren't loaded. Run the `export` command above or check your `.env` file.

**AWS returns 0 resources in discovery**
AWS Config may not be enabled. Run `bash scripts/aws-setup.sh` or enable it manually in the AWS Console (us-east-1).

**GitHub API returns 401 or 403**
Your token needs `repo` and `read:org` scopes. Create a new Personal Access Token (classic) at https://github.com/settings/tokens.

**`export $(cat .env ...)` doesn't work on Windows**
Use the PowerShell command in the setup section above.

**Resources not found but they exist**
Check your region. Everything must be in **us-east-1**. Look at the region selector in the top right of the AWS Console.

**NVD API is slow or times out**
Use `--skip-nvd` flag. NVD rate-limits to 5 requests per 30 seconds without an API key.
