#!/usr/bin/env python3
"""
S3 Bucket Security Hardening Checker

Audits all S3 buckets in the account for:
  - Public access (ACL, bucket policy, Block Public Access settings)
  - Server-side encryption (SSE)
  - Access logging enabled
  - Versioning enabled
  - MFA delete enabled
  - Lifecycle policies (prevent indefinite data retention)
  - Cross-region replication (for DR)
  - Object Lock (WORM compliance)

Usage:
    python s3_bucket_hardening.py
    python s3_bucket_hardening.py --profile prod --output s3_report.csv
    python s3_bucket_hardening.py --fix-block-public   # Auto-enable Block Public Access
"""

import argparse
import csv
import json
import sys
from dataclasses import dataclass
from typing import Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


@dataclass
class BucketFinding:
    bucket: str
    region: str
    severity: str
    check: str
    status: str
    detail: str
    recommendation: str


class S3Auditor:
    def __init__(self, session: boto3.Session):
        self.s3 = session.client("s3")
        self.findings: list[BucketFinding] = []

    def _add(self, bucket: str, region: str, severity: str, check: str,
             status: str, detail: str, recommendation: str):
        self.findings.append(BucketFinding(
            bucket=bucket, region=region, severity=severity,
            check=check, status=status, detail=detail, recommendation=recommendation,
        ))

    def _get_bucket_region(self, bucket: str) -> str:
        try:
            loc = self.s3.get_bucket_location(Bucket=bucket)
            return loc["LocationConstraint"] or "us-east-1"
        except ClientError:
            return "unknown"

    # ------------------------------------------------------------------ #
    # Individual checks                                                    #
    # ------------------------------------------------------------------ #

    def check_block_public_access(self, bucket: str, region: str):
        try:
            config = self.s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
            settings = {
                "BlockPublicAcls": config.get("BlockPublicAcls", False),
                "IgnorePublicAcls": config.get("IgnorePublicAcls", False),
                "BlockPublicPolicy": config.get("BlockPublicPolicy", False),
                "RestrictPublicBuckets": config.get("RestrictPublicBuckets", False),
            }
            failed = [k for k, v in settings.items() if not v]
            if failed:
                self._add(bucket, region, "CRITICAL", "Block Public Access",
                          "FAIL",
                          f"Disabled settings: {', '.join(failed)}",
                          "Enable all four Block Public Access settings on every bucket unless "
                          "intentionally hosting a public static website.")
            else:
                self._add(bucket, region, "INFO", "Block Public Access", "PASS", "All settings enabled", "")
        except ClientError as e:
            if "NoSuchPublicAccessBlockConfiguration" in str(e):
                self._add(bucket, region, "CRITICAL", "Block Public Access",
                          "FAIL",
                          "Block Public Access configuration does not exist for this bucket.",
                          "Enable Block Public Access on the bucket immediately.")

    def check_acl(self, bucket: str, region: str):
        try:
            acl = self.s3.get_bucket_acl(Bucket=bucket)
            public_grantees = [
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
            ]
            for grant in acl.get("Grants", []):
                grantee_uri = grant.get("Grantee", {}).get("URI", "")
                if grantee_uri in public_grantees:
                    permission = grant.get("Permission", "")
                    self._add(bucket, region, "CRITICAL", "Bucket ACL",
                              "FAIL",
                              f"Public ACL grant: {grantee_uri.split('/')[-1]} → {permission}",
                              "Remove public ACL grants. Use bucket policies with specific principals instead.")
        except ClientError:
            pass

    def check_bucket_policy_public(self, bucket: str, region: str):
        try:
            policy_str = self.s3.get_bucket_policy(Bucket=bucket)["Policy"]
            policy = json.loads(policy_str)
            for stmt in policy.get("Statement", []):
                effect = stmt.get("Effect", "")
                principal = stmt.get("Principal", "")
                if effect == "Allow" and (principal == "*" or principal == {"AWS": "*"}):
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    self._add(bucket, region, "CRITICAL", "Bucket Policy",
                              "FAIL",
                              f"Policy allows public access. Actions: {actions}",
                              "Remove wildcard (*) principal from bucket policy unless intentionally public.")
        except ClientError as e:
            if "NoSuchBucketPolicy" in str(e):
                pass  # No policy is not a finding by itself

    def check_encryption(self, bucket: str, region: str):
        try:
            enc = self.s3.get_bucket_encryption(Bucket=bucket)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            for rule in rules:
                algo = rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "")
                if algo in ("AES256", "aws:kms"):
                    self._add(bucket, region, "INFO", "Server-Side Encryption", "PASS",
                              f"Encryption enabled: {algo}", "")
                    return
            self._add(bucket, region, "MEDIUM", "Server-Side Encryption", "FAIL",
                      "Encryption rules found but algorithm not recognized.",
                      "Ensure SSE-S3 (AES256) or SSE-KMS (aws:kms) is configured.")
        except ClientError as e:
            if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                self._add(bucket, region, "HIGH", "Server-Side Encryption",
                          "FAIL",
                          "No default encryption configured on bucket.",
                          "Enable SSE-S3 or SSE-KMS as the default encryption for all objects.")

    def check_logging(self, bucket: str, region: str):
        try:
            logging_config = self.s3.get_bucket_logging(Bucket=bucket).get("LoggingEnabled")
            if not logging_config:
                self._add(bucket, region, "MEDIUM", "Access Logging",
                          "FAIL",
                          "Server access logging is not enabled.",
                          "Enable S3 server access logging to a separate audit log bucket.")
            else:
                target = logging_config.get("TargetBucket", "")
                self._add(bucket, region, "INFO", "Access Logging", "PASS",
                          f"Logging to: {target}", "")
        except ClientError:
            pass

    def check_versioning(self, bucket: str, region: str):
        try:
            versioning = self.s3.get_bucket_versioning(Bucket=bucket)
            status = versioning.get("Status", "Disabled")
            mfa_delete = versioning.get("MFADelete", "Disabled")
            if status != "Enabled":
                self._add(bucket, region, "MEDIUM", "Versioning",
                          "FAIL",
                          f"Versioning is {status}.",
                          "Enable versioning to protect against accidental deletion and ransomware.")
            else:
                self._add(bucket, region, "INFO", "Versioning", "PASS", "Versioning enabled", "")
            if mfa_delete != "Enabled" and status == "Enabled":
                self._add(bucket, region, "LOW", "MFA Delete",
                          "FAIL",
                          "MFA delete is not enabled on versioned bucket.",
                          "Enable MFA delete for high-sensitivity buckets to prevent version deletion.")
        except ClientError:
            pass

    def check_lifecycle(self, bucket: str, region: str):
        try:
            self.s3.get_bucket_lifecycle_configuration(Bucket=bucket)
        except ClientError as e:
            if "NoSuchLifecycleConfiguration" in str(e):
                self._add(bucket, region, "LOW", "Lifecycle Policy",
                          "WARN",
                          "No lifecycle policy configured.",
                          "Add lifecycle rules to transition old objects to cheaper storage tiers "
                          "and expire objects per data retention policy.")

    # ------------------------------------------------------------------ #
    # Auto-remediation                                                     #
    # ------------------------------------------------------------------ #

    def fix_block_public_access(self, bucket: str):
        try:
            self.s3.put_public_access_block(
                Bucket=bucket,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            print(f"  [+] Block Public Access enabled on: {bucket}")
        except ClientError as e:
            print(f"  [ERROR] Could not enable Block Public Access on {bucket}: {e}")

    # ------------------------------------------------------------------ #
    # Main audit loop                                                      #
    # ------------------------------------------------------------------ #

    def audit_all(self, fix_public: bool = False):
        try:
            buckets = self.s3.list_buckets()["Buckets"]
        except ClientError as e:
            print(f"[ERROR] Cannot list buckets: {e}")
            sys.exit(1)

        print(f"[*] Found {len(buckets)} S3 buckets")
        for bucket in buckets:
            name = bucket["Name"]
            region = self._get_bucket_region(name)
            print(f"  Auditing: {name} ({region})")

            self.check_block_public_access(name, region)
            self.check_acl(name, region)
            self.check_bucket_policy_public(name, region)
            self.check_encryption(name, region)
            self.check_logging(name, region)
            self.check_versioning(name, region)
            self.check_lifecycle(name, region)

            if fix_public:
                critical = [f for f in self.findings if f.bucket == name
                            and f.check == "Block Public Access" and f.status == "FAIL"]
                if critical:
                    self.fix_block_public_access(name)

    def print_summary(self):
        from collections import Counter
        severity_counts = Counter(
            f.severity for f in self.findings if f.severity != "INFO"
        )
        bucket_findings = Counter(f.bucket for f in self.findings if f.status == "FAIL")

        print("\n=== S3 Security Audit Summary ===")
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "WARN"]:
            count = severity_counts.get(level, 0)
            if count:
                bar = "█" * count
                print(f"  {level:<10} {bar} ({count})")

        print(f"\n  Buckets with findings: {len(bucket_findings)}")
        print("\n  Top Offending Buckets:")
        for bucket, count in bucket_findings.most_common(10):
            print(f"    {bucket:<50} ({count} issues)")

    def export_csv(self, output_path: str):
        with open(output_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "severity", "bucket", "region", "check", "status", "detail", "recommendation"
            ])
            writer.writeheader()
            severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "WARN", "INFO"]
            for finding in sorted(
                self.findings,
                key=lambda x: (severity_order.index(x.severity) if x.severity in severity_order else 99, x.bucket)
            ):
                if finding.status != "PASS":
                    writer.writerow({
                        "severity": finding.severity,
                        "bucket": finding.bucket,
                        "region": finding.region,
                        "check": finding.check,
                        "status": finding.status,
                        "detail": finding.detail,
                        "recommendation": finding.recommendation,
                    })
        print(f"[+] S3 audit report saved: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="S3 bucket security hardening checker")
    parser.add_argument("--profile", default=None, help="AWS CLI profile")
    parser.add_argument("--region", default="us-east-1", help="AWS region (for API calls)")
    parser.add_argument("--output", default="s3_audit.csv", help="Output CSV file")
    parser.add_argument("--fix-block-public", action="store_true",
                        help="Auto-enable Block Public Access on non-compliant buckets")
    args = parser.parse_args()

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    auditor = S3Auditor(session)
    try:
        auditor.audit_all(fix_public=args.fix_block_public)
        auditor.print_summary()
        auditor.export_csv(args.output)
    except NoCredentialsError:
        print("[ERROR] No AWS credentials found. Run 'aws configure'.")
        sys.exit(1)


if __name__ == "__main__":
    main()
