#!/bin/bash
ACCT="567947664730"
ROLE="arn:aws:iam::${ACCT}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"

echo "=== Config recorder ==="
cat > /tmp/recorder.json << 'REOF'
{"name":"default","roleARN":"arn:aws:iam::567947664730:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"}
REOF
cat > /tmp/recgroup.json << 'GEOF'
{"allSupported":true,"includeGlobalResourceTypes":true}
GEOF
aws configservice put-configuration-recorder --configuration-recorder file:///tmp/recorder.json --recording-group file:///tmp/recgroup.json --region us-east-1
echo "Config recorder created"

echo "=== CloudTrail bucket policy ==="
cat > /tmp/trailpolicy.json << PEOF
{"Version":"2012-10-17","Statement":[{"Sid":"AWSCloudTrailAclCheck","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::workshop-encrypted-grc2026"},{"Sid":"AWSCloudTrailWrite","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::workshop-encrypted-grc2026/AWSLogs/${ACCT}/*","Condition":{"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control"}}}]}
PEOF
aws s3api put-bucket-policy --bucket workshop-encrypted-grc2026 --policy file:///tmp/trailpolicy.json
echo "Bucket policy set"

echo "=== CloudTrail ==="
aws cloudtrail create-trail --name workshop-audit-trail --s3-bucket-name workshop-encrypted-grc2026 --is-multi-region-trail --no-enable-log-file-validation --region us-east-1
echo "Trail created"

aws cloudtrail start-logging --name workshop-audit-trail --region us-east-1
echo "Trail logging started"

echo "=== Done ==="
