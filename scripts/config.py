# ──────────────────────────────────────────────────────────────
# INTENTIONAL FINDING — DO NOT USE IN PRODUCTION
# This file exists to demonstrate credential detection.
# These are fake credentials that should be caught by scanners.
# ──────────────────────────────────────────────────────────────

# Hardcoded AWS credentials (intentional finding: IA-5, SC-28)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Hardcoded database password (intentional finding: IA-5)
DB_PASSWORD = "SuperSecret123!"

# Hardcoded API token in source (intentional finding: IA-5)
INTERNAL_API_KEY = "sk-demo-not-real-key-for-workshop-finding-only"
