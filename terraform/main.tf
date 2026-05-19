# ──────────────────────────────────────────────────────────────
# INTENTIONAL MISCONFIGURATIONS — Workshop Demo
# These Terraform configs contain security findings that
# Trivy and the OSCAL pipeline will detect during assessment.
# DO NOT deploy this to any real environment.
# ──────────────────────────────────────────────────────────────

provider "aws" {
  region = "us-east-1"
}

# SC-7: Security group with unrestricted ingress (0.0.0.0/0)
resource "aws_security_group" "wide_open" {
  name        = "workshop-wide-open"
  description = "Intentionally misconfigured — allows all inbound traffic"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# SC-28: S3 bucket without encryption
resource "aws_s3_bucket" "unencrypted" {
  bucket = "workshop-terraform-unencrypted"
}

# SC-28: No server-side encryption configuration
# (intentionally missing aws_s3_bucket_server_side_encryption_configuration)

# SC-7: S3 bucket without public access block
# (intentionally missing aws_s3_bucket_public_access_block)

# AC-6: IAM policy with wildcard permissions
resource "aws_iam_policy" "overly_permissive" {
  name        = "workshop-overly-permissive"
  description = "Intentional finding — wildcard permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# AU-2: CloudWatch log group without retention
resource "aws_cloudwatch_log_group" "no_retention" {
  name = "workshop-no-retention"
  # retention_in_days intentionally omitted — logs kept forever (finding: AU-2)
}

# SC-8: ALB listener on HTTP without redirect to HTTPS
resource "aws_lb_listener" "http_no_redirect" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/workshop/50dc6c495c0c9188"
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "OK"
      status_code  = "200"
    }
  }
}

# SC-12: KMS key without rotation
resource "aws_kms_key" "no_rotation" {
  description         = "Workshop key — rotation intentionally disabled"
  enable_key_rotation = false
}
