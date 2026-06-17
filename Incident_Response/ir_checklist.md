# Incident Response First-Responder Checklist

Universal checklist for the first 60 minutes of any security incident. Adapt based on incident type.

---

## Before You Touch Anything

```
[ ] Is the incident still active / ongoing?
[ ] Are you authorized to respond to this system?
[ ] Is there a risk of destroying evidence if you act too quickly?
[ ] Have you documented the time you started responding? (UTC: ____________)
[ ] Have you notified the Incident Commander?
```

---

## Identification (0–15 min)

### Gather Basic Facts
```
[ ] Incident type: [ ] Malware  [ ] Phishing  [ ] Breach  [ ] DDoS  [ ] Insider  [ ] Other
[ ] Affected hosts (list):
[ ] Affected users (list):
[ ] First signs of compromise (time, alert, who reported):
[ ] Is data at risk? What type? (PII / PHI / Financial / IP / Other):
[ ] Is the incident still active?
[ ] Estimated blast radius (how many systems):
```

### Assign Severity
```
[ ] P1 — Critical: Active compromise, exfil in progress, ransomware spreading
[ ] P2 — High: Confirmed malware, contained breach
[ ] P3 — Medium: Suspicious activity, unconfirmed
[ ] P4 — Low: Policy violation, no malicious intent
```

---

## Evidence Collection (15–30 min)

**Golden rule: Collect volatile evidence first (memory → processes → network → disk).**

### On the Affected Host (if accessible)
```bash
# System info
hostname; date; whoami; ipconfig /all   # Windows
hostname; date; id; ifconfig            # Linux

# Running processes
tasklist /v /fo csv > processes.csv     # Windows
ps auxf > processes.txt                 # Linux

# Active network connections
netstat -anob > netstat.txt             # Windows
ss -tulnp > netstat.txt                 # Linux

# Logged-in users
query user                              # Windows
who; w                                  # Linux

# Recently run commands
Get-History | Export-Csv history.csv    # PowerShell
cat ~/.bash_history > history.txt       # Linux

# Scheduled tasks
schtasks /query /fo LIST /v > tasks.txt # Windows
crontab -l; ls /etc/cron* > cron.txt   # Linux

# Recently modified files (last 24h)
# Windows: Use EDR or check $MFT
find / -mtime -1 -type f 2>/dev/null > recent_files.txt  # Linux
```

### Memory Capture (if feasible and authorized)
```
[ ] Tool available: Winpmem (Windows) / LiME (Linux) / AVML
[ ] Sufficient disk space on collection drive?
[ ] Hash the memory dump after collection (SHA256)
```

### Log Collection
```
[ ] Windows Event Logs: Security, System, Application
[ ] EDR telemetry exported
[ ] Web/proxy logs for affected host
[ ] VPN/RDP logs if remote access is suspected
[ ] SIEM raw events for affected host (last 72 hours minimum)
```

### Chain of Custody
```
[ ] Document: Who collected evidence, when, from where, using what tool
[ ] Hash all collected files (MD5 + SHA256)
[ ] Store evidence on read-only media or immutable storage
[ ] Do NOT modify original evidence
```

---

## Containment (30–60 min)

### Host-Level Containment
```
[ ] EDR network isolation deployed (preferred — preserves forensics)
[ ] Host removed from production VLAN (if EDR not available)
[ ] Remote sessions terminated
[ ] Account(s) used by attacker disabled / locked
[ ] Malicious scheduled tasks / persistence removed
```

### Network-Level Containment
```
[ ] Attacker IP(s) blocked at perimeter firewall
[ ] C2 domains/IPs added to DNS blocklist + proxy blocklist
[ ] Egress traffic from affected subnet restricted
[ ] Lateral movement paths identified and blocked (SMB, RDP, WinRM)
```

### Identity Containment
```
[ ] Compromised accounts: [ ] Disabled  [ ] Password reset  [ ] MFA re-enrolled
[ ] Service accounts on affected hosts: [ ] Rotated
[ ] Kerberos tickets invalidated (if domain compromise suspected)
[ ] OAuth tokens / API keys revoked (if applicable)
```

---

## Communication (Throughout)

### Internal Notifications
```
[ ] Incident Commander notified immediately
[ ] Manager / Team lead notified
[ ] Executive team notified (P1/P2 only)
[ ] Legal counsel notified (any potential PII/PHI/PAN exposure)
[ ] HR notified (if insider threat)
[ ] IT/Help Desk briefed (to handle user calls)
```

### Documentation
```
[ ] Incident ticket created in [Jira/ServiceNow]: Ticket #: ________
[ ] All actions logged in ticket with timestamps
[ ] Screenshot of key evidence captured
[ ] Communication log maintained (who told whom, when)
```

---

## Preliminary Threat Assessment

After evidence collection, answer:

```
1. Initial Access Vector:
   [ ] Phishing email    [ ] Exposed service  [ ] Stolen credentials
   [ ] Supply chain      [ ] Insider          [ ] Unknown

2. Is attacker still present?
   [ ] Yes — ACTIVE (prioritize eviction)
   [ ] No  — DORMANT or COMPLETE
   [ ] Unknown

3. What has the attacker accessed?
   [ ] Credentials       [ ] PII/PHI/PAN      [ ] Intellectual property
   [ ] Source code       [ ] Financial data    [ ] Infrastructure access
   [ ] Unknown

4. Has data been exfiltrated?
   [ ] Confirmed         [ ] Suspected        [ ] No evidence         [ ] Unknown

5. MITRE ATT&CK initial mapping:
   Initial Access: T_______
   Execution:      T_______
   Persistence:    T_______
   Other:          T_______
```

---

## Hourly Status Update Template

```
STATUS UPDATE — [YYYY-MM-DD HH:MM UTC]
Incident: [Ticket #]
Severity: [P1/P2/P3/P4]

SITUATION:
[2-3 sentences on what happened and current state]

CONTAINMENT:
[Is the incident contained? What isolation actions are in place?]

AFFECTED ASSETS:
[List hosts, users, data types]

NEXT ACTIONS (next 1 hour):
1. 
2. 
3. 

OPEN QUESTIONS:
-
-

ETA TO FULL CONTAINMENT: [Estimate]
```
