# Cloud Security Projects

AWS security automation scripts for IAM auditing, S3 hardening, and CloudTrail log analysis.

## Contents

| File | Description |
|------|-------------|
| [aws_iam_audit.py](./aws_iam_audit.py) | Audit IAM users, roles, and policies for over-permission and stale keys |
| [s3_bucket_hardening.py](./s3_bucket_hardening.py) | Check all S3 buckets for public access, encryption, logging gaps |
| [cloudtrail_analyzer.py](./cloudtrail_analyzer.py) | Analyze CloudTrail logs for suspicious API calls and privilege escalation |

## Prerequisites

```bash
pip install boto3 python-dateutil

# Configure AWS credentials
aws configure  # or use IAM role / environment variables
```

**Required IAM Permissions (read-only audit):**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:List*", "iam:Get*",
      "s3:List*", "s3:GetBucket*",
      "cloudtrail:LookupEvents", "cloudtrail:GetTrail*",
      "logs:FilterLogEvents"
    ],
    "Resource": "*"
  }]
}
```

## Common Security Findings

| Finding | Severity | Script |
|---------|----------|--------|
| Root account has active access keys | Critical | aws_iam_audit.py |
| IAM user with admin policy attached directly | High | aws_iam_audit.py |
| Access key not rotated in > 90 days | High | aws_iam_audit.py |
| S3 bucket publicly accessible | Critical | s3_bucket_hardening.py |
| S3 bucket without server-side encryption | Medium | s3_bucket_hardening.py |
| CloudTrail disabled or not logging all regions | High | cloudtrail_analyzer.py |
| Root account login detected | Critical | cloudtrail_analyzer.py |
| IAM privilege escalation via policy attachment | High | cloudtrail_analyzer.py |
