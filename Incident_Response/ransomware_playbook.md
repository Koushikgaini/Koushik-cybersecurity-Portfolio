# Ransomware Incident Response Playbook

**Version:** 2.1  
**Last Updated:** 2024-06-01  
**Owner:** Security Operations  
**Classification:** Internal Use Only  

---

## Overview

This playbook covers the full lifecycle response to a ransomware incident — from initial detection through containment, eradication, recovery, and post-incident review. It is aligned with NIST SP 800-61r2 and the CIS Controls v8 framework.

**Activate this playbook when:**
- Mass file encryption or extension changes are detected
- Ransom notes appear on endpoints or file shares
- VSS shadow copies are being deleted
- EDR alerts fire for known ransomware TTPs (T1486, T1490)

---

## Roles & Responsibilities

| Role | Responsibilities |
|------|----------------|
| Incident Commander (IC) | Coordinates all IR activities, final decision authority |
| SOC Lead | Alert triage, initial investigation, SIEM queries |
| IR Engineer | Forensic collection, malware analysis, IOC extraction |
| Network Engineer | Firewall rule deployment, traffic blocking, segmentation |
| Systems Admin | Host isolation, backup restoration, system rebuild |
| Legal/Compliance | Breach notification decisions, law enforcement contact |
| Communications Lead | Internal comms, executive briefing, PR if needed |

---

## Phase 1: Detection & Initial Triage (0–30 minutes)

### Detection Sources

| Alert Type | Expected Source | Splunk Query |
|-----------|----------------|-------------|
| Mass file modification | EDR / File integrity monitoring | `index=edr event_type=file_modify | stats count by host \| where count > 500` |
| Shadow copy deletion | Windows Event logs | `EventCode=4688 CommandLine="*vssadmin*delete*shadows*"` |
| Ransom note creation | EDR file creation events | `index=edr file_name IN ("README*.txt","DECRYPT*.html","HOW_TO_RECOVER*")` |
| Known ransomware hash | EDR / AV | Vendor-specific |
| C2 traffic | Proxy / Firewall | Unusual outbound to Tor, known RaaS IPs |

### Immediate Actions (First Responder)

1. **DO NOT reboot the affected system** — volatile memory may contain encryption keys.
2. **DO NOT pay the ransom** without executive and legal approval.
3. **Page the Incident Commander immediately** — this is a P1.
4. **Capture the following before any action:**
   - Screenshot of ransom note (including wallet address and contact info)
   - Running processes (`tasklist /v` or EDR process list)
   - Active network connections (`netstat -anob`)
   - List of recently modified files

### Scope Assessment Questions

```
- How many hosts appear affected? (check EDR dashboard)
- Is encryption still active / spreading?
- Are any domain controllers, backup servers, or NAS devices affected?
- Is there evidence of data exfiltration before encryption (double extortion)?
- When did encryption begin? (check earliest ransom note timestamp)
- What strain of ransomware? (check extension, ransom note, ID Ransomware)
```

**Identify the strain:** Submit ransom note and encrypted file sample to [ID Ransomware](https://id-ransomware.malwarehunterteam.com/) (offline copy preferred).

---

## Phase 2: Containment (30 minutes – 4 hours)

### 2.1 Network Isolation

**Priority order of isolation:**

```
1. Isolate domain controllers (after confirming backups are clean)
2. Isolate backup systems and NAS
3. Isolate actively encrypting hosts
4. Segment affected network subnet at firewall
5. Block all outbound from affected VLAN (stop exfiltration)
```

**Isolation methods (preference order):**

| Method | Speed | Risk |
|--------|-------|------|
| EDR network isolation (CrowdStrike contain) | Fast | Low |
| VLAN reassignment at switch | Fast | Medium |
| Physical cable unplug | Immediate | Loss of volatile data |
| Firewall ACL block | Fast | May miss east-west |

**DO NOT** isolate via remote desktop — if RDP is the infection vector, closing the session may trigger additional encryption.

### 2.2 Disable Spread Vectors

```powershell
# Disable SMB (CAUTION: may impact file sharing — coordinate with sysadmin)
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force

# Block ADMIN$ and IPC$ shares temporarily
net share ADMIN$ /delete
net share IPC$ /delete

# Disable scheduled tasks (attacker persistence)
schtasks /change /disable /tn "*"  # Use with caution

# Force group policy update to push emergency policies
gpupdate /force
```

### 2.3 Credential Reset

Assume **all credentials are compromised** when domain controllers are affected:

1. Reset all service account passwords (start with accounts with network access)
2. Reset domain administrator passwords (offline if domain is compromised)
3. Revoke all active Kerberos tickets (`klist purge` on all workstations, or rotate krbtgt twice)
4. Disable accounts for users on affected systems pending investigation

### 2.4 Preserve Evidence

```bash
# Memory dump (before isolation if possible) — use Winpmem
winpmem_mini_x64_rc2.exe memory.dmp

# Collect Windows event logs
wevtutil epl System system.evtx
wevtutil epl Security security.evtx
wevtutil epl Application application.evtx

# Collect prefetch files (execution artifacts)
xcopy /s C:\Windows\Prefetch\ .\prefetch\

# Hash all collected evidence (chain of custody)
certutil -hashfile memory.dmp SHA256
```

---

## Phase 3: Eradication (4–24 hours)

### 3.1 Malware Removal

1. Identify all infected hosts via EDR search for known ransomware hash/behavior.
2. For each infected host:
   - **Preferred:** Wipe and rebuild from golden image (fastest, cleanest)
   - **Alternative:** EDR-assisted remediation + full AV scan + manual artifact removal
3. Remove all ransomware artifacts:
   - Malware binaries and drops
   - Scheduled tasks / run keys / services created by ransomware
   - Modified system files (compare against known-good baseline)

### 3.2 Initial Access Root Cause

**Determine how ransomware entered the environment:**

| Vector | Investigation Steps |
|--------|-------------------|
| Phishing email | Review email gateway logs, find initial payload email |
| Exposed RDP | Check firewall logs — was RDP externally accessible? Check EventCode 4624 LogonType=10 |
| Unpatched vulnerability | Correlate with Nessus scan results, check exploit timestamps |
| Compromised credentials | Check dark web for leaked creds, review failed/successful logins |
| Supply chain | Review recent software installs/updates |

### 3.3 Verify Backup Integrity

**Before restoring, verify backups are clean:**

```
1. Confirm backup server was NOT connected to affected network during incident
2. Check backup logs — any unusual access or modification to backup files?
3. Restore a single test host from backup, scan with updated AV signatures
4. Confirm restored system shows no signs of compromise
5. DO NOT connect the restored host to production until verified clean
```

---

## Phase 4: Recovery (24–72 hours)

### Recovery Priority Order

```
Tier 1 (0–24h):   Active Directory, DNS, DHCP, authentication systems
Tier 2 (24–48h):  Core production systems, customer-facing applications
Tier 3 (48–72h):  Internal tools, non-critical applications
Tier 4 (72h+):    Historical data, archival systems
```

### Restoration Steps (Per Host)

```
[ ] Verify host is fully isolated before restoration begins
[ ] Restore from pre-incident backup (verify backup date predates infection)
[ ] Apply all outstanding security patches before rejoining network
[ ] Install/update EDR agent and verify it's reporting
[ ] Run full AV scan with updated signatures
[ ] Change all local account passwords
[ ] Enable audit logging
[ ] Test application functionality
[ ] Rejoin network in monitored state (elevated logging for 30 days)
[ ] Confirm normal operation with business owner
```

### Re-enable Services Checklist

```
[ ] Restore file shares (verify no encrypted files in share)
[ ] Restore email flow (check for malicious rules created by attacker)
[ ] Restore backup jobs (update schedule, verify connectivity)
[ ] Re-enable remote access (VPN, RDP) with MFA enforced
[ ] Remove emergency firewall rules (document any that should remain)
```

---

## Phase 5: Post-Incident Review

Complete within **5 business days** of incident closure.

### Lessons Learned Document

1. **Timeline:** Complete attack timeline from initial access to recovery
2. **Root Cause:** How did the attacker gain initial access?
3. **Detection Gap:** When did the attack start vs. when did we detect it?
4. **Response Effectiveness:** What worked well? What slowed us down?
5. **Control Failures:** Which security controls failed or were bypassed?
6. **Recommendations:** Specific, actionable improvements

### Metrics to Capture

| Metric | Value |
|--------|-------|
| Mean Time to Detect (MTTD) | |
| Mean Time to Contain (MTTC) | |
| Mean Time to Recover (MTTR) | |
| Number of hosts affected | |
| Estimated data at risk | |
| Business downtime (hours) | |
| Recovery cost estimate | |

### Mandatory Notification Checklist

| Audience | Trigger | Timeline |
|---------|---------|---------|
| Executive team | All P1 incidents | Immediate (first 1 hour) |
| Board of Directors | Data breach confirmed | Within 24 hours |
| Legal counsel | Any indication of PII exposure | Within 2 hours |
| Law enforcement (FBI, CISA) | Critical infrastructure or large breach | Within 24 hours |
| GDPR notification (if EU data) | PII breach confirmed | Within 72 hours |
| HIPAA notification | PHI exposure | Within 60 days (breach) |
| Affected individuals | PII confirmed compromised | Per state law (typically 30–60 days) |

---

## Ransomware Strain Quick Reference

| Family | Known Extensions | Ransom Note | Decryptor Available? |
|--------|----------------|------------|---------------------|
| LockBit 3.0 | `.lockbit` | `[ID].README.txt` | No |
| BlackCat/ALPHV | Multiple | `RECOVER-[ext]-FILES.txt` | Sometimes |
| Cl0p | `.clop` | `ClopReadMe.txt` | Sometimes (old versions) |
| Akira | `.akira` | `akira_readme.txt` | No |
| Play | `.play` | `ReadMe.txt` | No |
| Rhysida | `.rhysida` | `CriticalBreachDetected.pdf` | Partial (2024) |

Check [No More Ransom](https://www.nomoreransom.org) for available decryptors before considering payment.
