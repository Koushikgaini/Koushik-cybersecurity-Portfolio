#!/usr/bin/env python3
"""
AWS IAM Security Audit

Checks for common IAM misconfigurations:
  - Root account with active access keys
  - Users with admin policies attached directly
  - Stale access keys (> 90 days without rotation)
  - Inactive users (no login in > 90 days)
  - Users without MFA
  - Roles with overly broad trust policies (trust *)
  - Password policy weaknesses

Usage:
    python aws_iam_audit.py
    python aws_iam_audit.py --profile prod --output iam_audit.csv
    python aws_iam_audit.py --region us-east-1 --min-key-age 90
"""

import argparse
import csv
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


ADMIN_POLICY_ARNS = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
}

STALE_KEY_DAYS = 90
INACTIVE_USER_DAYS = 90


@dataclass
class Finding:
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW
    category: str          # IAM_USER / IAM_ROLE / IAM_POLICY / ROOT
    resource: str
    finding: str
    detail: str
    recommendation: str


class IAMAuditor:
    def __init__(self, session: boto3.Session, stale_days: int = STALE_KEY_DAYS):
        self.iam = session.client("iam")
        self.sts = session.client("sts")
        self.stale_days = stale_days
        self.findings: list[Finding] = []
        self.account_id = ""

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _age_days(self, dt) -> int:
        if dt is None:
            return 0
        if isinstance(dt, str):
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (self._now() - dt).days

    def _add(self, severity: str, category: str, resource: str,
             finding: str, detail: str, recommendation: str):
        self.findings.append(Finding(severity, category, resource, finding, detail, recommendation))

    # ------------------------------------------------------------------ #
    # Account-level checks                                                 #
    # ------------------------------------------------------------------ #

    def check_account_id(self):
        try:
            self.account_id = self.sts.get_caller_identity()["Account"]
            print(f"[*] Auditing AWS account: {self.account_id}")
        except ClientError as e:
            print(f"[ERROR] Could not get account ID: {e}")

    def check_root_account(self):
        print("[*] Checking root account ...")
        try:
            summary = self.iam.get_account_summary()["SummaryMap"]

            if summary.get("AccountAccessKeysPresent", 0) > 0:
                self._add(
                    "CRITICAL", "ROOT", "root",
                    "Root account has active access keys",
                    "Root account has programmatic access keys — these should never exist.",
                    "Delete root account access keys immediately. Use IAM roles instead.",
                )

            if summary.get("AccountMFAEnabled", 0) == 0:
                self._add(
                    "CRITICAL", "ROOT", "root",
                    "Root account MFA not enabled",
                    "Root account does not have MFA enabled.",
                    "Enable hardware MFA or virtual MFA on the root account immediately.",
                )
        except ClientError as e:
            print(f"[WARN] Could not check root account: {e}")

    def check_password_policy(self):
        print("[*] Checking password policy ...")
        try:
            policy = self.iam.get_account_password_policy()["PasswordPolicy"]
            issues = []
            if policy.get("MinimumPasswordLength", 0) < 14:
                issues.append(f"minimum length {policy.get('MinimumPasswordLength')} < 14")
            if not policy.get("RequireUppercaseCharacters"):
                issues.append("uppercase not required")
            if not policy.get("RequireLowercaseCharacters"):
                issues.append("lowercase not required")
            if not policy.get("RequireNumbers"):
                issues.append("numbers not required")
            if not policy.get("RequireSymbols"):
                issues.append("symbols not required")
            max_age = policy.get("MaxPasswordAge", 999)
            if max_age > 90:
                issues.append(f"max age {max_age} days > 90")
            if not policy.get("HardExpiry"):
                issues.append("hard expiry not enforced")
            if issues:
                self._add(
                    "MEDIUM", "IAM_POLICY", "AccountPasswordPolicy",
                    "Weak IAM password policy",
                    "Issues: " + "; ".join(issues),
                    "Enforce: min 14 chars, upper/lower/number/symbol, max age 90 days, hard expiry.",
                )
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                self._add(
                    "HIGH", "IAM_POLICY", "AccountPasswordPolicy",
                    "No IAM password policy configured",
                    "No account-level password policy is set.",
                    "Configure a strong password policy. Consider moving to SSO/IdP instead.",
                )

    # ------------------------------------------------------------------ #
    # User checks                                                          #
    # ------------------------------------------------------------------ #

    def check_users(self):
        print("[*] Checking IAM users ...")
        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                self._check_user_mfa(username)
                self._check_user_keys(username)
                self._check_user_last_login(user)
                self._check_user_policies(username)

    def _check_user_mfa(self, username: str):
        try:
            mfa_devices = self.iam.list_mfa_devices(UserName=username)["MFADevices"]
            if not mfa_devices:
                self._add(
                    "HIGH", "IAM_USER", username,
                    "MFA not enabled",
                    f"User {username} has no MFA devices registered.",
                    "Require MFA for all IAM users. Consider enforcing via SCP or IAM condition.",
                )
        except ClientError:
            pass

    def _check_user_keys(self, username: str):
        try:
            keys = self.iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
            for key in keys:
                key_id = key["AccessKeyId"]
                status = key["Status"]
                age = self._age_days(key["CreateDate"])

                if status == "Active" and age > self.stale_days:
                    self._add(
                        "HIGH", "IAM_USER", username,
                        f"Stale access key ({age} days old)",
                        f"Key {key_id} has not been rotated in {age} days.",
                        f"Rotate access keys every {self.stale_days} days. "
                        f"Consider using IAM roles instead of long-lived keys.",
                    )

                if status == "Inactive" and age > 30:
                    self._add(
                        "LOW", "IAM_USER", username,
                        f"Inactive access key not deleted ({age} days old)",
                        f"Key {key_id} is inactive but still exists for {age} days.",
                        "Delete inactive access keys. Inactive keys should be removed within 30 days.",
                    )
        except ClientError:
            pass

    def _check_user_last_login(self, user: dict):
        username = user["UserName"]
        last_login = user.get("PasswordLastUsed")
        created = user.get("CreateDate")
        if last_login:
            age = self._age_days(last_login)
            if age > INACTIVE_USER_DAYS:
                self._add(
                    "MEDIUM", "IAM_USER", username,
                    f"Inactive user account ({age} days since last login)",
                    f"Last console login: {age} days ago.",
                    "Disable or delete inactive IAM user accounts. Review with account owner.",
                )
        elif created and self._age_days(created) > 30:
            self._add(
                "LOW", "IAM_USER", username,
                "User has never logged in to console",
                f"Account created {self._age_days(created)} days ago with no console login.",
                "Review if account is still needed. Remove if unused.",
            )

    def _check_user_policies(self, username: str):
        try:
            attached = self.iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
            for policy in attached:
                if policy["PolicyArn"] in ADMIN_POLICY_ARNS:
                    self._add(
                        "HIGH", "IAM_USER", username,
                        f"Admin policy directly attached: {policy['PolicyName']}",
                        f"Policy {policy['PolicyArn']} grants broad administrative access.",
                        "Follow principle of least privilege. Use groups and roles instead of "
                        "directly attaching admin policies to users.",
                    )

            inline = self.iam.list_user_policies(UserName=username)["PolicyNames"]
            if inline:
                self._add(
                    "MEDIUM", "IAM_USER", username,
                    f"Inline policies attached ({len(inline)} found)",
                    f"Inline policies: {', '.join(inline)}",
                    "Prefer managed policies over inline policies for auditability and reuse.",
                )
        except ClientError:
            pass

    # ------------------------------------------------------------------ #
    # Role checks                                                          #
    # ------------------------------------------------------------------ #

    def check_roles(self):
        print("[*] Checking IAM roles ...")
        paginator = self.iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                role_name = role["RoleName"]
                trust = role.get("AssumeRolePolicyDocument", {})
                self._check_role_trust(role_name, trust)
                self._check_role_policies(role_name)

    def _check_role_trust(self, role_name: str, trust: dict):
        for stmt in trust.get("Statement", []):
            principal = stmt.get("Principal", {})
            if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                self._add(
                    "CRITICAL", "IAM_ROLE", role_name,
                    "Role trust policy allows ANY AWS principal (* )",
                    f"Trust policy grants assume-role to all AWS principals.",
                    "Restrict trust policy to specific account IDs, roles, or services.",
                )

    def _check_role_policies(self, role_name: str):
        try:
            attached = self.iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
            for policy in attached:
                if policy["PolicyArn"] in ADMIN_POLICY_ARNS:
                    if role_name not in ("OrganizationAccountAccessRole", "AWSReservedSSO_AdministratorAccess"):
                        self._add(
                            "HIGH", "IAM_ROLE", role_name,
                            f"Admin policy attached to role: {policy['PolicyName']}",
                            f"Role has {policy['PolicyArn']} — full administrative access.",
                            "Review if admin access is necessary. Apply least-privilege permissions.",
                        )
        except ClientError:
            pass

    # ------------------------------------------------------------------ #
    # Reporting                                                            #
    # ------------------------------------------------------------------ #

    def print_summary(self):
        from collections import Counter
        counts = Counter(f.severity for f in self.findings)
        print(f"\n=== IAM Audit Summary — Account {self.account_id} ===")
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = counts.get(level, 0)
            bar = "█" * count
            print(f"  {level:<10} {bar} ({count})")
        print(f"\n  Total findings: {len(self.findings)}")

        if self.findings:
            print("\n  Critical & High Findings:")
            for f in sorted(self.findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x.severity)):
                if f.severity in ("CRITICAL", "HIGH"):
                    print(f"  [{f.severity}] {f.resource}: {f.finding}")

    def export_csv(self, output_path: str):
        with open(output_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["severity","category","resource","finding","detail","recommendation"])
            writer.writeheader()
            for finding in sorted(self.findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x.severity)):
                writer.writerow({
                    "severity": finding.severity,
                    "category": finding.category,
                    "resource": finding.resource,
                    "finding": finding.finding,
                    "detail": finding.detail,
                    "recommendation": finding.recommendation,
                })
        print(f"[+] Audit report saved: {output_path}")

    def run(self):
        self.check_account_id()
        self.check_root_account()
        self.check_password_policy()
        self.check_users()
        self.check_roles()
        self.print_summary()


def main():
    parser = argparse.ArgumentParser(description="AWS IAM security audit")
    parser.add_argument("--profile", help="AWS CLI profile name", default=None)
    parser.add_argument("--region", help="AWS region", default="us-east-1")
    parser.add_argument("--output", help="CSV output path", default="iam_audit.csv")
    parser.add_argument("--min-key-age", type=int, default=STALE_KEY_DAYS,
                        help=f"Days before access key is considered stale (default: {STALE_KEY_DAYS})")
    args = parser.parse_args()

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
    except Exception as e:
        print(f"[ERROR] Could not create AWS session: {e}")
        sys.exit(1)

    auditor = IAMAuditor(session, stale_days=args.min_key_age)
    try:
        auditor.run()
        auditor.export_csv(args.output)
    except NoCredentialsError:
        print("[ERROR] No AWS credentials found. Run 'aws configure' or set environment variables.")
        sys.exit(1)


if __name__ == "__main__":
    main()
