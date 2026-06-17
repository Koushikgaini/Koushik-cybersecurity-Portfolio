# Threat Intelligence Projects

Threat intelligence tooling and research artifacts including IOC tracking, MITRE ATT&CK mapping, and APT analysis templates.

## Contents

| File | Description |
|------|-------------|
| [ioc_tracker.py](./ioc_tracker.py) | Automated IOC enrichment via VirusTotal & AbuseIPDB |
| [mitre_attack_mapping.md](./mitre_attack_mapping.md) | ATT&CK technique reference for common threat scenarios |
| [threat_reports/apt_report_template.md](./threat_reports/apt_report_template.md) | Structured APT threat intelligence report template |
| [threat_reports/darkweb_intel_template.md](./threat_reports/darkweb_intel_template.md) | Dark web monitoring report template |

## IOC Types Tracked

| IOC Type | Examples | Tools |
|----------|---------|-------|
| IP Addresses | C2 servers, scanners | AbuseIPDB, Shodan |
| Domains / URLs | Phishing, malware delivery | VirusTotal, URLhaus |
| File Hashes (MD5/SHA256) | Malware samples | VirusTotal, MalwareBazaar |
| Email Addresses | Phishing senders | Hunter.io, HIBP |
| CVEs | Exploited vulnerabilities | NVD, CISA KEV |
