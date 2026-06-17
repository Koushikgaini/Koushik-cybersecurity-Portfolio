# MITRE ATT&CK Technique Reference

Practical reference mapping common attack scenarios to ATT&CK techniques, with detection guidance and Splunk query pointers.

---

## Initial Access (TA0001)

| ID | Technique | Sub-Technique | Detection Signals | Splunk Query |
|----|-----------|--------------|------------------|-------------|
| T1566.001 | Phishing | Spearphishing Attachment | Email with executable attachments, macro-enabled docs | `PHI-001` in [splunk_queries.md](../SOC_Analyst/splunk_queries.md) |
| T1566.002 | Phishing | Spearphishing Link | Proxy logs with newly registered domains, URL shorteners | `PHI-002` |
| T1190 | Exploit Public-Facing App | — | IDS alerts, 500 errors with unusual user agents, SQLi patterns | `WEB-001` |
| T1133 | External Remote Services | — | VPN/RDP logins from unusual geographies, off-hours | `AUTH-003` |
| T1078 | Valid Accounts | Domain Accounts | Login from unexpected IP, impossible travel | `AUTH-001` |

---

## Execution (TA0002)

| ID | Technique | Sub-Technique | Detection Signals |
|----|-----------|--------------|------------------|
| T1059.001 | Command & Scripting | PowerShell | `-EncodedCommand`, `IEX`, `DownloadString` in commandline |
| T1059.003 | Command & Scripting | Windows Command Shell | `cmd.exe` spawned by Office apps, weird parent processes |
| T1047 | WMI | — | `wmic.exe` with remote host args, `Win32_Process.Create` |
| T1053.005 | Scheduled Task | — | `schtasks /create` by non-admin, unusual task paths |
| T1204.002 | User Execution | Malicious File | User executed attachment from temp/downloads folder |

---

## Persistence (TA0003)

| ID | Technique | Sub-Technique | Detection Signals |
|----|-----------|--------------|------------------|
| T1547.001 | Boot/Logon Autostart | Registry Run Keys | New values in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| T1053.005 | Scheduled Task | — | Tasks created outside business hours, unusual binary paths |
| T1136.001 | Create Account | Local Account | EventCode 4720 by non-admin users |
| T1078.002 | Valid Accounts | Domain Accounts | Service accounts logging in interactively |
| T1505.003 | Server Software Component | Web Shell | Anomalous .aspx/.php writes to web root, unusual child processes of web server |

---

## Privilege Escalation (TA0004)

| ID | Technique | Sub-Technique | Detection Signals |
|----|-----------|--------------|------------------|
| T1055 | Process Injection | — | Unexpected `CreateRemoteThread`, memory write to other process |
| T1134 | Access Token Manipulation | — | `SeDebugPrivilege` usage, token impersonation calls |
| T1548.002 | Abuse Elevation Control | Bypass UAC | `fodhelper.exe`, `eventvwr.exe` spawning high-integrity shells |
| T1068 | Exploitation for Privilege Escalation | — | Kernel exploit patterns, PrintNightmare, Dirty Pipe |

---

## Defense Evasion (TA0005)

| ID | Technique | Sub-Technique | Detection Signals |
|----|-----------|--------------|------------------|
| T1027 | Obfuscated Files | — | Base64 blobs in scripts, XOR-encoded payloads |
| T1562.001 | Impair Defenses | Disable Security Tools | `net stop` on AV services, registry disabling Windows Defender |
| T1070.001 | Indicator Removal | Clear Windows Event Logs | EventCode 1102/104 (log cleared) |
| T1036.005 | Masquerading | Match Legitimate Name | `svchost.exe` running from non-system32 path |
| T1218.011 | System Binary Proxy Exec | Rundll32 | `rundll32.exe` with URL arguments or uncommon DLLs |

---

## Credential Access (TA0006)

| ID | Technique | Sub-Technique | Detection Signals |
|----|-----------|--------------|------------------|
| T1003.001 | OS Credential Dumping | LSASS Memory | `lsass.exe` memory access by non-system processes, procdump usage |
| T1110.001 | Brute Force | Password Guessing | >10 failed logins in 5 min from single IP |
| T1110.003 | Brute Force | Password Spraying | Many accounts failing same password, slow rate across many IPs |
| T1555.003 | Credentials from Password Stores | Credentials from Web Browsers | Browser process reading credential databases |
| T1539 | Steal Web Session Cookie | — | Concurrent sessions from different geo IPs/ASNs |

---

## Discovery (TA0007)

| ID | Technique | Sub-Technique | Detection Signals |
|----|-----------|--------------|------------------|
| T1046 | Network Service Discovery | — | Nmap-like patterns, port scans from internal hosts |
| T1087.002 | Account Discovery | Domain Account | `net user /domain`, `Get-ADUser` by non-admin |
| T1069.002 | Permission Groups Discovery | Domain Groups | `net group "Domain Admins"`, `whoami /groups` |
| T1082 | System Information Discovery | — | `systeminfo`, `reg query` bursts in short window |
| T1016 | System Network Config Discovery | — | `ipconfig /all`, `arp -a`, `route print` |

---

## Lateral Movement (TA0008)

| ID | Technique | Sub-Technique | Detection Signals |
|----|-----------|--------------|------------------|
| T1021.001 | Remote Services | RDP | EventCode 4624 LogonType=10 from internal IPs to multiple hosts |
| T1021.002 | Remote Services | SMB/Windows Admin Shares | Lateral `net use \\host\admin$` or `IPC$` access |
| T1550.002 | Use Alternate Auth Material | Pass the Hash | NTLM auth EventCode 4624 from unusual sources |
| T1563.002 | Remote Service Session Hijacking | RDP Hijacking | `tscon.exe` usage, session ID manipulation |

---

## Exfiltration (TA0010)

| ID | Technique | Sub-Technique | Detection Signals |
|----|-----------|--------------|------------------|
| T1041 | Exfil Over C2 Channel | — | Large outbound to known C2, periodic large transfers |
| T1048.003 | Exfil Over Alt Protocol | Exfil Over Unencrypted | FTP, HTTP POST with unusual file types/sizes |
| T1071.004 | App Layer Protocol | DNS | High volume unique subdomains to single domain (DNS tunneling) |
| T1567.002 | Exfil to Cloud Storage | Exfil to Code Repository | Unusual `git push` volumes, GitHub/Dropbox upload spikes |

---

## Impact (TA0040)

| ID | Technique | Sub-Technique | Detection Signals |
|----|-----------|--------------|------------------|
| T1486 | Data Encrypted for Impact | Ransomware | Mass file extension changes, vssadmin shadow delete, ransom notes |
| T1490 | Inhibit System Recovery | — | `vssadmin delete shadows`, `bcdedit /set recoveryenabled no` |
| T1485 | Data Destruction | — | Mass file deletion, `cipher /w`, format commands |
| T1498 | Network Denial of Service | — | SYN flood, UDP amplification traffic patterns |

---

## Quick Reference: High-Priority Technique Combos

### Ransomware Kill Chain
```
T1566.001 → T1204.002 → T1059.001 → T1082 → T1486 + T1490
Phishing → User exec → PowerShell → Recon → Encrypt + Kill recovery
```

### Supply Chain / Living off the Land
```
T1195 → T1078 → T1036.005 → T1070.001 → T1041
Supply chain compromise → Valid creds → Masquerade → Clear logs → Exfil
```

### Insider Threat Pattern
```
T1078 → T1087 → T1005 → T1048 → T1567
Valid account → Account discovery → Local data collection → Alt channel exfil
```
