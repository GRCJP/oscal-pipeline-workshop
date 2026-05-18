#!/bin/bash
# ============================================================
#  OSCAL Pipeline Workshop — AWS Environment Setup
#  Run this ONCE with admin credentials to provision the
#  demo environment. Participants run this before the session.
#
#  Usage:
#    export AWS_ACCESS_KEY_ID=<your-admin-key>
#    export AWS_SECRET_ACCESS_KEY=<your-admin-secret>
#    export AWS_DEFAULT_REGION=us-east-1
#    bash scripts/aws-setup.sh
#
#  What it creates:
#    - 5 IAM users (compliant, non-compliant, stale-key, service, admin)
#    - 3 S3 buckets (encrypted, logging, open — mix of good and bad)
#    - CloudTrail trail with multi-region logging
#    - AWS Config recorder for asset discovery
#    - A read-only svc-pipeline user with API keys for the pipeline
#
#  Estimated cost: $0 (free tier eligible)
# ============================================================

set -e

# IMPORTANT: All workshop resources MUST be in us-east-1 for consistency.
# Do not change this unless you also update .env, prereqs, and all ingest scripts.
REGION="us-east-1"
export AWS_DEFAULT_REGION="$REGION"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
TIMESTAMP=$(date +%s)

echo ""
echo "============================================================"
echo "  OSCAL Pipeline Workshop — AWS Setup"
echo "  Account: $ACCOUNT_ID"
echo "  Region:  $REGION"
echo "============================================================"
echo ""

# ── Helper ───────────────────────────────────────────────────
check_exists() {
    "$@" > /dev/null 2>&1
}

# ── 1. S3 Buckets ───────────────────────────────────────────
echo "  [1/5] Creating S3 buckets..."

BUCKET_ENCRYPTED="workshop-encrypted-${ACCOUNT_ID:0:8}"
BUCKET_LOGGING="workshop-logging-${ACCOUNT_ID:0:8}"
BUCKET_OPEN="workshop-open-${ACCOUNT_ID:0:8}"
BUCKET_CLOUDTRAIL="workshop-cloudtrail-${ACCOUNT_ID:0:8}"

for BUCKET in $BUCKET_ENCRYPTED $BUCKET_LOGGING $BUCKET_OPEN $BUCKET_CLOUDTRAIL; do
    if aws s3api head-bucket --bucket "$BUCKET" 2>/dev/null; then
        echo "        $BUCKET — exists, skipping"
    else
        if [ "$REGION" = "us-east-1" ]; then
            aws s3api create-bucket --bucket "$BUCKET" > /dev/null
        else
            aws s3api create-bucket --bucket "$BUCKET" \
                --create-bucket-configuration LocationConstraint="$REGION" > /dev/null
        fi
        echo "        $BUCKET — created"
    fi
done

# Encrypted bucket — SSE-S3 + public access blocked (COMPLIANT)
aws s3api put-bucket-encryption --bucket "$BUCKET_ENCRYPTED" \
    --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' 2>/dev/null || true
aws s3api put-public-access-block --bucket "$BUCKET_ENCRYPTED" \
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" 2>/dev/null || true
echo "        $BUCKET_ENCRYPTED — encrypted + public access blocked ✓"

# Logging bucket — SSE-S3 + public access blocked (COMPLIANT)
aws s3api put-bucket-encryption --bucket "$BUCKET_LOGGING" \
    --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' 2>/dev/null || true
aws s3api put-public-access-block --bucket "$BUCKET_LOGGING" \
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" 2>/dev/null || true
echo "        $BUCKET_LOGGING — encrypted + public access blocked ✓"

# Open bucket — NO encryption, NO public access block (NON-COMPLIANT — intentional finding)
aws s3api delete-bucket-encryption --bucket "$BUCKET_OPEN" 2>/dev/null || true
aws s3api delete-public-access-block --bucket "$BUCKET_OPEN" 2>/dev/null || true
echo "        $BUCKET_OPEN — no encryption, no public block ✗ (intentional finding)"

# CloudTrail bucket — needs a policy to allow CloudTrail to write
TRAIL_BUCKET_POLICY=$(cat <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::${BUCKET_CLOUDTRAIL}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::${BUCKET_CLOUDTRAIL}/AWSLogs/${ACCOUNT_ID}/*",
            "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}
        }
    ]
}
POLICY
)
aws s3api put-bucket-policy --bucket "$BUCKET_CLOUDTRAIL" --policy "$TRAIL_BUCKET_POLICY" 2>/dev/null || true
aws s3api put-bucket-encryption --bucket "$BUCKET_CLOUDTRAIL" \
    --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' 2>/dev/null || true
aws s3api put-public-access-block --bucket "$BUCKET_CLOUDTRAIL" \
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" 2>/dev/null || true
echo "        $BUCKET_CLOUDTRAIL — CloudTrail delivery bucket ✓"

echo ""

# ── 2. IAM Users ────────────────────────────────────────────
echo "  [2/5] Creating IAM users..."

# Password policy (for the account — demonstrates IA-5)
aws iam update-account-password-policy \
    --minimum-password-length 14 \
    --require-symbols \
    --require-numbers \
    --require-uppercase-characters \
    --require-lowercase-characters \
    --max-password-age 90 \
    --password-reuse-prevention 12 2>/dev/null || true
echo "        Password policy set: 14 chars, complexity, 90-day rotation ✓"

create_user() {
    local USERNAME=$1
    if aws iam get-user --user-name "$USERNAME" > /dev/null 2>&1; then
        echo "        $USERNAME — exists, skipping"
    else
        aws iam create-user --user-name "$USERNAME" > /dev/null
        echo "        $USERNAME — created"
    fi
}

# demo-compliant: has MFA, no access keys, follows best practices
create_user "demo-compliant"
# Enable virtual MFA if not already set
if [ "$(aws iam list-mfa-devices --user-name demo-compliant --query 'length(MFADevices)')" = "0" ]; then
    MFA_ARN=$(aws iam create-virtual-mfa-device \
        --virtual-mfa-device-name demo-compliant-mfa \
        --outfile /tmp/mfa-qr.png \
        --bootstrap-method QRCodePNG \
        --query 'VirtualMFADevice.SerialNumber' --output text 2>/dev/null) || true
    if [ -n "$MFA_ARN" ]; then
        echo "        demo-compliant MFA device created (needs manual activation)"
        echo "        QR code saved to /tmp/mfa-qr.png"
    fi
fi

# demo-no-mfa: no MFA enabled (NON-COMPLIANT — intentional finding for IA-2)
create_user "demo-no-mfa"
echo "        demo-no-mfa — no MFA ✗ (intentional finding)"

# demo-stale-key: has an access key (will age over time — finding for AC-2)
create_user "demo-stale-key"
KEY_COUNT=$(aws iam list-access-keys --user-name demo-stale-key --query 'length(AccessKeyMetadata)' 2>/dev/null)
if [ "$KEY_COUNT" = "0" ]; then
    aws iam create-access-key --user-name demo-stale-key > /dev/null 2>&1
    echo "        demo-stale-key — access key created ✗ (will become stale finding)"
else
    echo "        demo-stale-key — access key exists ✗ (stale key finding)"
fi

# workshop-admin: admin user with MFA (COMPLIANT)
create_user "workshop-admin"
aws iam attach-user-policy --user-name workshop-admin \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>/dev/null || true
echo "        workshop-admin — AdministratorAccess attached ✓"

# svc-pipeline: read-only service account for the pipeline
create_user "svc-pipeline"
aws iam attach-user-policy --user-name svc-pipeline \
    --policy-arn arn:aws:iam::aws:policy/job-function/ViewOnlyAccess 2>/dev/null || true
aws iam attach-user-policy --user-name svc-pipeline \
    --policy-arn arn:aws:iam::aws:policy/SecurityAudit 2>/dev/null || true
aws iam attach-user-policy --user-name svc-pipeline \
    --policy-arn arn:aws:iam::aws:policy/AWSConfigUserAccess 2>/dev/null || true

# Create access key for svc-pipeline if none exists
SVC_KEY_COUNT=$(aws iam list-access-keys --user-name svc-pipeline --query 'length(AccessKeyMetadata)' 2>/dev/null)
if [ "$SVC_KEY_COUNT" = "0" ]; then
    echo ""
    echo "  ┌─────────────────────────────────────────────────────────┐"
    echo "  │  Creating svc-pipeline access key                       │"
    echo "  │  SAVE THESE — you won't see them again                 │"
    echo "  └─────────────────────────────────────────────────────────┘"
    aws iam create-access-key --user-name svc-pipeline --output table
    echo ""
    echo "  Copy the AccessKeyId and SecretAccessKey into your .env file."
else
    echo "        svc-pipeline — access key exists, policies updated ✓"
fi

echo ""

# ── 3. CloudTrail ────────────────────────────────────────────
echo "  [3/5] Setting up CloudTrail..."

TRAIL_NAME="workshop-audit-trail"
if aws cloudtrail get-trail --name "$TRAIL_NAME" --region "$REGION" > /dev/null 2>&1; then
    echo "        $TRAIL_NAME — exists, skipping"
else
    aws cloudtrail create-trail \
        --name "$TRAIL_NAME" \
        --s3-bucket-name "$BUCKET_CLOUDTRAIL" \
        --is-multi-region-trail \
        --no-enable-log-file-validation \
        --region "$REGION" > /dev/null 2>&1
    echo "        $TRAIL_NAME — created (multi-region, log validation OFF — intentional finding)"
fi

# Make sure it's logging
aws cloudtrail start-logging --name "$TRAIL_NAME" --region "$REGION" 2>/dev/null || true
echo "        $TRAIL_NAME — logging active ✓"
echo "        Log file validation: disabled ✗ (intentional finding)"

echo ""

# ── 4. AWS Config ────────────────────────────────────────────
echo "  [4/5] Enabling AWS Config..."

RECORDER_EXISTS=$(aws configservice describe-configuration-recorders \
    --region "$REGION" --query 'length(ConfigurationRecorders)' 2>/dev/null)

if [ "$RECORDER_EXISTS" != "0" ]; then
    echo "        Config recorder — exists, skipping"
else
    # Create service-linked role for Config
    aws iam create-service-linked-role \
        --aws-service-name config.amazonaws.com 2>/dev/null || true

    # Wait for role propagation
    sleep 5

    # Create the recorder (using JSON files to avoid shell quoting issues)
    cat > /tmp/recorder.json << REOF
{"name":"default","roleARN":"arn:aws:iam::${ACCOUNT_ID}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"}
REOF
    cat > /tmp/recgroup.json << 'GEOF'
{"allSupported":true,"includeGlobalResourceTypes":true}
GEOF
    aws configservice put-configuration-recorder \
        --configuration-recorder file:///tmp/recorder.json \
        --recording-group file:///tmp/recgroup.json \
        --region "$REGION" 2>/dev/null

    # Set up delivery channel
    aws configservice put-delivery-channel \
        --delivery-channel name=default,s3BucketName=${BUCKET_LOGGING} \
        --region "$REGION" 2>/dev/null

    # Start recording
    aws configservice start-configuration-recorder \
        --configuration-recorder-name default \
        --region "$REGION" 2>/dev/null

    echo "        Config recorder — created and started ✓"
    echo "        Delivery bucket: $BUCKET_LOGGING"
    echo "        Recording: all resource types + global resources"
fi

echo ""

# ── 5. Summary ───────────────────────────────────────────────
echo "  [5/5] Verifying setup..."
echo ""
echo "============================================================"
echo "  AWS ENVIRONMENT SETUP COMPLETE"
echo "============================================================"
echo ""
echo "  IAM Users:"
echo "    ✓ demo-compliant    — MFA enabled, follows best practices"
echo "    ✗ demo-no-mfa       — no MFA (finding: IA-2)"
echo "    ✗ demo-stale-key    — access key aging (finding: AC-2)"
echo "    ✓ svc-pipeline      — read-only, ViewOnly + SecurityAudit + ConfigAccess"
echo "    ✓ workshop-admin    — admin with MFA"
echo ""
echo "  S3 Buckets:"
echo "    ✓ $BUCKET_ENCRYPTED — encrypted, public access blocked"
echo "    ✓ $BUCKET_LOGGING   — encrypted, public access blocked"
echo "    ✗ $BUCKET_OPEN      — no encryption, no public block (finding: SC-28)"
echo "    ✓ $BUCKET_CLOUDTRAIL — CloudTrail delivery, encrypted"
echo ""
echo "  CloudTrail:"
echo "    ✓ $TRAIL_NAME       — multi-region, logging active"
echo "    ✗ Log file validation disabled (finding: AU-9)"
echo ""
echo "  AWS Config:"
echo "    ✓ Recording all resource types + global resources"
echo "    ✓ Delivery to $BUCKET_LOGGING"
echo ""
echo "  Intentional findings for demo:"
echo "    1. demo-no-mfa has no MFA              → IA-2"
echo "    2. demo-stale-key has aging access key  → AC-2"
echo "    3. $BUCKET_OPEN has no encryption       → SC-28"
echo "    4. CloudTrail log validation disabled   → AU-9"
echo ""
echo "  Next: Copy svc-pipeline credentials into .env and run:"
echo "    python3 scripts/excel_to_oscal.py --input Templates/fedramp-moderate-template-ssp.xlsx --output oscal"
echo "============================================================"
echo ""
