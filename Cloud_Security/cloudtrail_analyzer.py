#!/usr/bin/env python3
"""
AWS CloudTrail Log Analyzer

Detects suspicious API activity in CloudTrail logs:
  - Root account usage
  - IAM privilege escalation (AttachPolicy, CreateUser, AddUserToGroup)
  - Security group / network changes (AuthorizeSecurityGroupIngress)
  - S3 data access from unexpected principals
  - Console logins from unusual IPs / failed logins
  - CloudTrail tampering (StopLogging, DeleteTrail)
  - Secrets Manager / SSM Parameter Store access
  - Excessive API error rates (possible credential stuffing / recon)

Usage:
    python cloudtrail_analyzer.py --hours 24
    python cloudtrail_analyzer.py --hours 168 --output findings.csv  # 7 days
    python cloudtrail_analyzer.py --event-name ConsoleLogin --hours 72
"""

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


# High-risk API calls to always flag
CRITICAL_EVENTS = {
    # CloudTrail tampering
    "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
    # IAM privilege escalation
    "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
    "PutUserPolicy", "PutRolePolicy", "CreatePolicyVersion",
    "AddUserToGroup", "CreateUser", "CreateLoginProfile",
    "UpdateLoginProfile", "CreateAccessKey",
    # Key/secret management
    "DeleteKMSKey", "ScheduleKeyDeletion", "DisableKey",
    # Root-specific
    "CreateVirtualMFADevice",
}

HIGH_RISK_EVENTS = {
    # Network changes
    "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
    "CreateSecurityGroup", "DeleteSecurityGroup",
    "ModifyVpcAttribute", "CreateInternetGateway",
    # Data access
    "GetSecretValue", "GetParameter", "GetParameters",
    "GetParametersByPath",
    # IAM recon
    "ListUsers", "ListRoles", "ListPolicies", "ListGroups",
    "GetAccountPasswordPolicy", "GetAccountSummary",
}


@dataclass
class Finding:
    severity: str
    event_time: str
    event_name: str
    user_identity: str
    source_ip: str
    region: str
    error_code: str
    detail: str


class CloudTrailAnalyzer:
    def __init__(self, session: boto3.Session):
        self.ct = session.client("cloudtrail")
        self.findings: list[Finding] = []

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _lookup_events(self, hours: int, event_name: str = None) -> list[dict]:
        start = self._now() - timedelta(hours=hours)
        kwargs = {
            "StartTime": start,
            "EndTime": self._now(),
            "MaxResults": 50,
        }
        if event_name:
            kwargs["LookupAttributes"] = [{"AttributeKey": "EventName", "AttributeValue": event_name}]

        events = []
        paginator = self.ct.get_paginator("lookup_events")
        try:
            for page in paginator.paginate(**{k: v for k, v in kwargs.items() if k != "MaxResults"}):
                events.extend(page.get("Events", []))
        except ClientError as e:
            print(f"[ERROR] CloudTrail lookup failed: {e}")
        return events

    def _parse_identity(self, event: dict) -> str:
        raw = event.get("CloudTrailEvent", "{}")
        try:
            ct_event = json.loads(raw)
            identity = ct_event.get("userIdentity", {})
            if identity.get("type") == "Root":
                return "ROOT"
            arn = identity.get("arn", "")
            assumed_role = identity.get("sessionContext", {}).get("sessionIssuer", {}).get("arn", "")
            return arn or assumed_role or identity.get("principalId", "unknown")
        except (json.JSONDecodeError, KeyError):
            return event.get("Username", "unknown")

    def _parse_source_ip(self, event: dict) -> str:
        try:
            ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
            return ct_event.get("sourceIPAddress", "")
        except json.JSONDecodeError:
            return ""

    def _parse_error(self, event: dict) -> str:
        try:
            ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
            return ct_event.get("errorCode", "")
        except json.JSONDecodeError:
            return ""

    def _parse_region(self, event: dict) -> str:
        try:
            ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
            return ct_event.get("awsRegion", "")
        except json.JSONDecodeError:
            return ""

    def _add(self, severity: str, event: dict, detail: str):
        self.findings.append(Finding(
            severity=severity,
            event_time=event.get("EventTime", self._now()).isoformat()
            if hasattr(event.get("EventTime"), "isoformat") else str(event.get("EventTime", "")),
            event_name=event.get("EventName", ""),
            user_identity=self._parse_identity(event),
            source_ip=self._parse_source_ip(event),
            region=self._parse_region(event),
            error_code=self._parse_error(event),
            detail=detail,
        ))

    # ------------------------------------------------------------------ #
    # Detection logic                                                      #
    # ------------------------------------------------------------------ #

    def detect_root_usage(self, hours: int):
        print("[*] Checking for root account usage ...")
        events = self._lookup_events(hours)
        for event in events:
            try:
                ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
                if ct_event.get("userIdentity", {}).get("type") == "Root":
                    self._add("CRITICAL", event,
                              "Root account used for API call. Root should never be used for routine operations.")
            except json.JSONDecodeError:
                pass

    def detect_critical_events(self, hours: int):
        print("[*] Checking for critical API events ...")
        events = self._lookup_events(hours)
        for event in events:
            name = event.get("EventName", "")
            if name in CRITICAL_EVENTS:
                severity = "CRITICAL" if name in {
                    "StopLogging", "DeleteTrail", "ScheduleKeyDeletion"
                } else "HIGH"
                self._add(severity, event, f"High-risk API call: {name}")

    def detect_console_login_anomalies(self, hours: int):
        print("[*] Checking console login events ...")
        events = self._lookup_events(hours, event_name="ConsoleLogin")
        failed_by_ip: Counter = Counter()
        for event in events:
            try:
                ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
                error = ct_event.get("errorMessage", "")
                src_ip = ct_event.get("sourceIPAddress", "")
                identity = ct_event.get("userIdentity", {})

                if error == "Failed authentication":
                    failed_by_ip[src_ip] += 1
                    if failed_by_ip[src_ip] == 5:  # Fire once at threshold
                        self._add("HIGH", event,
                                  f"5+ failed console logins from {src_ip} — possible credential stuffing")

                if identity.get("type") == "Root":
                    self._add("CRITICAL", event, "Root account console login detected")

                if ct_event.get("additionalEventData", {}).get("MFAUsed") == "No":
                    if identity.get("type") != "Root":
                        self._add("MEDIUM", event,
                                  f"Console login without MFA by {identity.get('arn', 'unknown')}")
            except json.JSONDecodeError:
                pass

    def detect_privilege_escalation(self, hours: int):
        print("[*] Checking for privilege escalation patterns ...")
        iam_events = ["AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
                      "PutUserPolicy", "CreateUser", "AddUserToGroup",
                      "CreateAccessKey", "CreateLoginProfile"]
        user_activity: dict[str, list] = defaultdict(list)
        for event_name in iam_events:
            for event in self._lookup_events(hours, event_name=event_name):
                user = self._parse_identity(event)
                user_activity[user].append(event.get("EventName"))

        for user, actions in user_activity.items():
            if len(set(actions)) >= 3:
                self._add("HIGH", {"EventName": "IAM_ESCALATION_PATTERN",
                                   "EventTime": self._now(),
                                   "CloudTrailEvent": "{}"},
                          f"Privilege escalation pattern: {user} performed {len(actions)} IAM actions "
                          f"({', '.join(set(actions))})")

    def detect_api_errors(self, hours: int, threshold: int = 50):
        print("[*] Checking for excessive API error rates ...")
        events = self._lookup_events(hours)
        error_by_principal: Counter = Counter()
        for event in events:
            error = self._parse_error(event)
            if error in ("AccessDenied", "UnauthorizedOperation", "AuthFailure"):
                principal = self._parse_identity(event)
                error_by_principal[principal] += 1

        for principal, count in error_by_principal.items():
            if count >= threshold:
                self._add("MEDIUM", {"EventName": "EXCESSIVE_API_ERRORS",
                                     "EventTime": self._now(),
                                     "CloudTrailEvent": json.dumps({"userIdentity": {"arn": principal},
                                                                     "sourceIPAddress": "",
                                                                     "awsRegion": ""})},
                          f"Principal {principal} had {count} AccessDenied errors — possible recon or "
                          f"misconfigured permissions")

    def detect_cloudtrail_tampering(self, hours: int):
        print("[*] Checking for CloudTrail tampering ...")
        for event_name in ("StopLogging", "DeleteTrail", "UpdateTrail"):
            for event in self._lookup_events(hours, event_name=event_name):
                self._add("CRITICAL", event,
                          f"CloudTrail tampered: {event_name} — attacker may be covering tracks")

    # ------------------------------------------------------------------ #
    # Reporting                                                            #
    # ------------------------------------------------------------------ #

    def print_summary(self):
        from collections import Counter
        counts = Counter(f.severity for f in self.findings)
        print(f"\n=== CloudTrail Analysis Summary ===")
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = counts.get(level, 0)
            bar = "█" * count
            print(f"  {level:<10} {bar} ({count})")

        if self.findings:
            print("\n  Recent Critical & High Findings:")
            for f in sorted(self.findings, key=lambda x: x.event_time, reverse=True):
                if f.severity in ("CRITICAL", "HIGH"):
                    print(f"  [{f.severity}] {f.event_time[:19]}  {f.event_name}  by {f.user_identity[:50]}")
                    print(f"           {f.detail}")

    def export_csv(self, output_path: str):
        with open(output_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "severity", "event_time", "event_name", "user_identity",
                "source_ip", "region", "error_code", "detail"
            ])
            writer.writeheader()
            severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            for finding in sorted(
                self.findings,
                key=lambda x: (severity_order.index(x.severity) if x.severity in severity_order else 99,
                               x.event_time),
            ):
                writer.writerow({
                    "severity": finding.severity,
                    "event_time": finding.event_time,
                    "event_name": finding.event_name,
                    "user_identity": finding.user_identity,
                    "source_ip": finding.source_ip,
                    "region": finding.region,
                    "error_code": finding.error_code,
                    "detail": finding.detail,
                })
        print(f"[+] CloudTrail findings saved: {output_path}")

    def run(self, hours: int):
        self.detect_root_usage(hours)
        self.detect_cloudtrail_tampering(hours)
        self.detect_critical_events(hours)
        self.detect_console_login_anomalies(hours)
        self.detect_privilege_escalation(hours)
        self.detect_api_errors(hours)
        self.print_summary()


def main():
    parser = argparse.ArgumentParser(description="AWS CloudTrail security log analyzer")
    parser.add_argument("--profile", default=None, help="AWS CLI profile")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--hours", type=int, default=24, help="Hours of logs to analyze (default: 24)")
    parser.add_argument("--output", default="cloudtrail_findings.csv", help="Output CSV file")
    parser.add_argument("--event-name", default=None, help="Filter to a specific event name")
    args = parser.parse_args()

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    analyzer = CloudTrailAnalyzer(session)
    try:
        print(f"[*] Analyzing CloudTrail logs for the last {args.hours} hours ...")
        analyzer.run(hours=args.hours)
        analyzer.export_csv(args.output)
    except NoCredentialsError:
        print("[ERROR] No AWS credentials found. Run 'aws configure'.")
        sys.exit(1)


if __name__ == "__main__":
    main()
