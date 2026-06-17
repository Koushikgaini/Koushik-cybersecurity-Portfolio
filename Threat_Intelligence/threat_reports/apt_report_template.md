# APT Threat Intelligence Report Template

**Classification:** TLP:AMBER — Share with trusted partners only  
**Report ID:** CTI-YYYY-XXXX  
**Date:** YYYY-MM-DD  
**Analyst:** [Name]  
**Confidence Level:** [High / Medium / Low]

---

## Executive Summary

> *2-3 sentence summary of who the actor is, what they're after, and immediate relevance to your organization.*

---

## Threat Actor Profile

| Field | Details |
|-------|---------|
| **Actor Name** | [e.g., APT29 / Cozy Bear] |
| **Aliases** | [Known alternate names] |
| **Origin** | [Assessed nation-state or region] |
| **Motivation** | [Espionage / Financial / Hacktivism / Destructive] |
| **Active Since** | [Year] |
| **Targeted Sectors** | [Government, Finance, Healthcare, Energy, etc.] |
| **Targeted Regions** | [US, EU, APAC, etc.] |
| **Sophistication** | [Low / Medium / High / Nation-State] |

---

## Campaign Overview

### Campaign Name / Codename
[Internal tracking name]

### Timeframe
First observed: YYYY-MM-DD  
Last observed: YYYY-MM-DD (or "Ongoing as of YYYY-MM-DD")

### Objective
[What is the actor trying to achieve in this campaign? Data theft, ransomware, disruption, reconnaissance?]

### Victims
- Industry 1
- Industry 2
- Specific organizations (if publicly disclosed)

---

## Attack Chain (Kill Chain / ATT&CK)

### Stage 1: Initial Access
- **Vector:** [Phishing / Supply chain / Exploit / Purchased access]
- **Details:** [Describe specifically — e.g., "spearphishing emails with .lnk attachments impersonating HR department"]
- **ATT&CK:** T1566.001

### Stage 2: Execution
- **Method:** [Macro-enabled document, PowerShell, exploit code]
- **Details:** [Specific tooling used]
- **ATT&CK:** T1059.001

### Stage 3: Persistence
- **Method:** [Registry run key, scheduled task, service installation]
- **ATT&CK:** T1547.001

### Stage 4: Privilege Escalation
- **Method:** [UAC bypass, token manipulation, local exploit]
- **ATT&CK:** T1548.002

### Stage 5: Lateral Movement
- **Method:** [Pass-the-hash, RDP, WMI]
- **ATT&CK:** T1021.001

### Stage 6: Collection & Exfiltration
- **Data Targeted:** [Credentials, IP, financial records, PII]
- **Exfil Method:** [HTTPS to C2, DNS tunneling, cloud storage]
- **ATT&CK:** T1041, T1071.004

---

## Indicators of Compromise (IOCs)

### IP Addresses (C2 / Infrastructure)
| IP | ASN | Country | Purpose | First Seen | Confidence |
|----|-----|---------|---------|-----------|-----------|
| x.x.x.x | ASxxxxx | XX | C2 server | YYYY-MM-DD | High |

### Domains
| Domain | Registrar | First Seen | Purpose | Confidence |
|--------|----------|-----------|---------|-----------|
| malicious-domain.com | NameCheap | YYYY-MM-DD | Phishing page | High |

### File Hashes
| Hash (SHA256) | Filename | Type | Description | Confidence |
|--------------|---------|------|-------------|-----------|
| `abc123...` | update.exe | PE32 | Dropper | High |

### Email Indicators
| Field | Value |
|-------|-------|
| Sender domain | malicious-sender.com |
| Subject pattern | "Action Required: [Document Name]" |
| Header anomaly | SPF pass, DKIM fail |

---

## Malware Analysis

### Sample: [Malware Family Name]

**File Details:**
- Name: `filename.exe`
- Size: X bytes
- MD5: `...`
- SHA256: `...`
- Compile time: YYYY-MM-DD (may be forged)
- Packer: [UPX / None / Custom]

**Capabilities:**
- [ ] Keylogging
- [ ] Screenshot capture
- [ ] File exfiltration
- [ ] Lateral movement
- [ ] Persistence installation
- [ ] C2 communication (protocol: HTTPS / DNS / custom)

**C2 Communication:**
- Protocol: HTTPS with custom TLS fingerprint
- Beacon interval: Every X minutes ± jitter
- Encoding: Base64 + XOR key `0xXX`

---

## Detection Opportunities

### Network-Based Detection

```
# Suricata / Snort rule example
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"APT29 C2 Beacon Pattern";
  http.uri; content:"/update?id="; depth:10;
  http.header; content:"User-Agent: Mozilla/5.0 (compatible)";
  threshold: type limit, track by_src, count 1, seconds 300;
  sid:9000001; rev:1;
)
```

### Endpoint-Based Detection (Splunk)

```spl
index=windows_logs EventCode=4688
| where match(CommandLine, "(?i)(encoded|iex|downloadstring|webclient)")
| where ParentImage like "%winword.exe%" OR ParentImage like "%excel.exe%"
| table _time, ComputerName, AccountName, CommandLine, ParentImage
```

### YARA Rule (Malware Family)

```yara
rule APT_Backdoor_PLACEHOLDER {
  meta:
    author = "Koushik Gaini"
    description = "Detects [Malware Family] backdoor"
    date = "YYYY-MM-DD"
  strings:
    $c2_string = "User-Agent: Mozilla/5.0 (compatible)" ascii
    $mutex = "Global\\MTX_" ascii
    $xor_key = { 4D 5A ?? ?? 00 00 }
  condition:
    uint16(0) == 0x5A4D and 2 of them
}
```

---

## Mitigation Recommendations

| Priority | Control | Action |
|----------|---------|--------|
| P1 | Email filtering | Block macro-enabled documents from external senders |
| P1 | Endpoint protection | Enable PowerShell script block logging (EventCode 4104) |
| P2 | Network segmentation | Restrict outbound HTTPS to known-good domains only |
| P2 | Credential hygiene | Enforce MFA on all remote access; disable NTLM where possible |
| P3 | Threat hunting | Search for IOCs listed above in historical logs (90 days) |
| P3 | Patch management | Ensure all public-facing systems are patched against CVE-XXXX |

---

## Intelligence Sources

- [Source 1 — e.g., Mandiant, CrowdStrike, public blog]
- [Source 2 — ISAC sharing]
- [Source 3 — Internal analysis]

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | YYYY-MM-DD | Koushik Gaini | Initial draft |
| 1.1 | YYYY-MM-DD | | Added new IOCs |
