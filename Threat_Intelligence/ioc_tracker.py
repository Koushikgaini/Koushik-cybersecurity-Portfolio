#!/usr/bin/env python3
"""
IOC Tracker — Automated enrichment for IPs, domains, and file hashes.

Integrates with:
  - VirusTotal API v3 (IPs, domains, hashes)
  - AbuseIPDB API v2 (IP reputation)
  - URLhaus (domain/URL lookup)

Usage:
    python ioc_tracker.py --ip 185.220.101.47
    python ioc_tracker.py --domain malicious-site.com
    python ioc_tracker.py --hash d41d8cd98f00b204e9800998ecf8427e
    python ioc_tracker.py --file iocs.txt --output report.csv

Requirements:
    pip install requests python-dotenv
    Set VT_API_KEY and ABUSEIPDB_API_KEY in .env
"""

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
URLHAUS_BASE = "https://urlhaus-api.abuse.ch/v1"

RATE_LIMIT_DELAY = 15  # seconds between VT requests (free tier: 4/min)


class IOCTracker:
    def __init__(self, vt_key: str = VT_API_KEY, abuse_key: str = ABUSEIPDB_API_KEY):
        self.vt_key = vt_key
        self.abuse_key = abuse_key
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "IOC-Tracker/1.0"})
        self.results: list[dict] = []

    # ------------------------------------------------------------------ #
    # VirusTotal                                                           #
    # ------------------------------------------------------------------ #

    def _vt_get(self, endpoint: str) -> Optional[dict]:
        if not self.vt_key:
            print("[WARN] VT_API_KEY not set — skipping VirusTotal lookup")
            return None
        url = f"{VT_BASE}/{endpoint}"
        headers = {"x-apikey": self.vt_key}
        try:
            resp = self.session.get(url, headers=headers, timeout=15)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            print(f"[ERROR] VirusTotal request failed: {e}")
            return None

    def enrich_ip_vt(self, ip: str) -> dict:
        data = self._vt_get(f"ip_addresses/{ip}")
        if not data:
            return {}
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "vt_malicious": stats.get("malicious", 0),
            "vt_suspicious": stats.get("suspicious", 0),
            "vt_total_engines": sum(stats.values()),
            "vt_country": attrs.get("country", ""),
            "vt_as_owner": attrs.get("as_owner", ""),
            "vt_reputation": attrs.get("reputation", 0),
            "vt_tags": ", ".join(attrs.get("tags", [])),
        }

    def enrich_domain_vt(self, domain: str) -> dict:
        data = self._vt_get(f"domains/{domain}")
        if not data:
            return {}
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "vt_malicious": stats.get("malicious", 0),
            "vt_suspicious": stats.get("suspicious", 0),
            "vt_total_engines": sum(stats.values()),
            "vt_categories": json.dumps(attrs.get("categories", {})),
            "vt_creation_date": attrs.get("creation_date", ""),
            "vt_reputation": attrs.get("reputation", 0),
        }

    def enrich_hash_vt(self, file_hash: str) -> dict:
        data = self._vt_get(f"files/{file_hash}")
        if not data:
            return {}
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "vt_malicious": stats.get("malicious", 0),
            "vt_suspicious": stats.get("suspicious", 0),
            "vt_total_engines": sum(stats.values()),
            "vt_name": attrs.get("meaningful_name", ""),
            "vt_type": attrs.get("type_description", ""),
            "vt_size": attrs.get("size", 0),
            "vt_tags": ", ".join(attrs.get("tags", [])),
        }

    # ------------------------------------------------------------------ #
    # AbuseIPDB                                                            #
    # ------------------------------------------------------------------ #

    def enrich_ip_abuseipdb(self, ip: str) -> dict:
        if not self.abuse_key:
            print("[WARN] ABUSEIPDB_API_KEY not set — skipping AbuseIPDB lookup")
            return {}
        headers = {"Key": self.abuse_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
        try:
            resp = self.session.get(
                f"{ABUSEIPDB_BASE}/check", headers=headers, params=params, timeout=15
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "abuse_reports": data.get("totalReports", 0),
                "abuse_country": data.get("countryCode", ""),
                "abuse_isp": data.get("isp", ""),
                "abuse_is_tor": data.get("isTor", False),
                "abuse_domain": data.get("domain", ""),
                "abuse_last_reported": data.get("lastReportedAt", ""),
            }
        except requests.RequestException as e:
            print(f"[ERROR] AbuseIPDB request failed: {e}")
            return {}

    # ------------------------------------------------------------------ #
    # URLhaus                                                              #
    # ------------------------------------------------------------------ #

    def enrich_url_urlhaus(self, url_or_domain: str) -> dict:
        try:
            resp = self.session.post(
                f"{URLHAUS_BASE}/url/",
                data={"url": url_or_domain},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("query_status") == "no_results":
                return {"urlhaus_status": "not_found"}
            return {
                "urlhaus_status": data.get("url_status", ""),
                "urlhaus_threat": data.get("threat", ""),
                "urlhaus_date_added": data.get("date_added", ""),
                "urlhaus_tags": ", ".join(data.get("tags") or []),
            }
        except requests.RequestException as e:
            print(f"[ERROR] URLhaus request failed: {e}")
            return {}

    # ------------------------------------------------------------------ #
    # Public interface                                                     #
    # ------------------------------------------------------------------ #

    def _verdict(self, vt_malicious: int, abuse_score: int = 0) -> str:
        if vt_malicious >= 10 or abuse_score >= 80:
            return "MALICIOUS"
        if vt_malicious >= 3 or abuse_score >= 40:
            return "SUSPICIOUS"
        if vt_malicious >= 1 or abuse_score >= 10:
            return "LOW RISK"
        return "CLEAN"

    def check_ip(self, ip: str) -> dict:
        print(f"[*] Checking IP: {ip}")
        result = {
            "ioc_type": "IP",
            "ioc_value": ip,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
        vt = self.enrich_ip_vt(ip)
        abuse = self.enrich_ip_abuseipdb(ip)
        result.update(vt)
        result.update(abuse)
        result["verdict"] = self._verdict(
            vt.get("vt_malicious", 0), abuse.get("abuse_score", 0)
        )
        self.results.append(result)
        time.sleep(RATE_LIMIT_DELAY)
        return result

    def check_domain(self, domain: str) -> dict:
        print(f"[*] Checking domain: {domain}")
        result = {
            "ioc_type": "Domain",
            "ioc_value": domain,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
        vt = self.enrich_domain_vt(domain)
        urlhaus = self.enrich_url_urlhaus(domain)
        result.update(vt)
        result.update(urlhaus)
        result["verdict"] = self._verdict(vt.get("vt_malicious", 0))
        self.results.append(result)
        time.sleep(RATE_LIMIT_DELAY)
        return result

    def check_hash(self, file_hash: str) -> dict:
        print(f"[*] Checking hash: {file_hash}")
        result = {
            "ioc_type": "Hash",
            "ioc_value": file_hash,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
        vt = self.enrich_hash_vt(file_hash)
        result.update(vt)
        result["verdict"] = self._verdict(vt.get("vt_malicious", 0))
        self.results.append(result)
        time.sleep(RATE_LIMIT_DELAY)
        return result

    def process_file(self, filepath: str):
        """
        Process a text file with one IOC per line.
        Auto-detects type based on format.
        """
        path = Path(filepath)
        if not path.exists():
            print(f"[ERROR] File not found: {filepath}")
            sys.exit(1)

        lines = [l.strip() for l in path.read_text().splitlines() if l.strip() and not l.startswith("#")]
        print(f"[*] Processing {len(lines)} IOCs from {filepath}")

        import re
        ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        hash_re = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")

        for line in lines:
            if ip_re.match(line):
                self.check_ip(line)
            elif hash_re.match(line):
                self.check_hash(line)
            else:
                self.check_domain(line)

    def export_csv(self, output_path: str):
        if not self.results:
            print("[WARN] No results to export")
            return
        fieldnames = sorted({k for r in self.results for k in r.keys()})
        with open(output_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.results)
        print(f"[+] Report saved to {output_path}")

    def print_summary(self):
        verdicts = [r.get("verdict", "UNKNOWN") for r in self.results]
        print("\n=== IOC Enrichment Summary ===")
        for verdict in ["MALICIOUS", "SUSPICIOUS", "LOW RISK", "CLEAN"]:
            count = verdicts.count(verdict)
            bar = "█" * count
            print(f"  {verdict:<12} {bar} ({count})")
        print(f"\n  Total checked: {len(self.results)}")


def main():
    parser = argparse.ArgumentParser(description="IOC enrichment tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip", help="Single IP address to check")
    group.add_argument("--domain", help="Single domain to check")
    group.add_argument("--hash", help="Single file hash (MD5/SHA1/SHA256)")
    group.add_argument("--file", help="Text file with one IOC per line")
    parser.add_argument("--output", help="CSV output file path", default="ioc_report.csv")
    args = parser.parse_args()

    tracker = IOCTracker()

    if args.ip:
        result = tracker.check_ip(args.ip)
        print(json.dumps(result, indent=2))
    elif args.domain:
        result = tracker.check_domain(args.domain)
        print(json.dumps(result, indent=2))
    elif args.hash:
        result = tracker.check_hash(args.hash)
        print(json.dumps(result, indent=2))
    elif args.file:
        tracker.process_file(args.file)

    tracker.print_summary()

    if args.output and tracker.results:
        tracker.export_csv(args.output)


if __name__ == "__main__":
    main()
