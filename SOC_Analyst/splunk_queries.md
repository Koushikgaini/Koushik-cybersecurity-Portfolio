# Splunk SPL Query Library

Production-ready Splunk queries for detecting common attack patterns. All queries are mapped to MITRE ATT&CK techniques.

---

## 1. Phishing & Email Threats

### Suspicious Email Attachment Types
```spl
index=email_logs sourcetype=mail
| where match(attachment_name, "\.(exe|vbs|bat|ps1|js|hta|docm|xlsm|iso|img)$")
| stats count by sender, recipient, attachment_name, subject
| where count > 0
| sort -count
```
**ATT&CK:** T1566.001 — Spearphishing Attachment

### Email with Encoded Payloads
```spl
index=email_logs sourcetype=mail body="*base64*" OR body="*powershell*" OR body="*cmd.exe*"
| eval risk="high"
| table _time, sender, recipient, subject, risk
```
**ATT&CK:** T1566.001, T1027 — Obfuscated Files

---

## 2. Brute Force & Authentication

### SSH Brute Force Detection (>10 failures in 5 min)
```spl
index=linux_logs sourcetype=syslog "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| bucket _time span=5m
| stats count by src_ip, _time
| where count > 10
| sort -count
```
**ATT&CK:** T1110.001 — Brute Force: Password Guessing

### Multiple Account Lockouts — Possible Credential Stuffing
```spl
index=windows_logs EventCode=4740
| stats count by TargetUserName, IpAddress
| where count > 3
| sort -count
| rename TargetUserName as "Locked Account", IpAddress as "Source IP"
```
**ATT&CK:** T1110.004 — Credential Stuffing

### Successful Login After Multiple Failures
```spl
index=windows_logs (EventCode=4625 OR EventCode=4624)
| eval status=if(EventCode=4624,"success","failure")
| stats values(status) as statuses, count(eval(status="failure")) as failures by SubjectUserName, IpAddress
| where failures > 5 AND mvfind(statuses,"success") >= 0
| table SubjectUserName, IpAddress, failures
```
**ATT&CK:** T1110 — Brute Force (successful follow-through)

---

## 3. Lateral Movement

### Pass-the-Hash (PtH) Indicators
```spl
index=windows_logs EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM
| where NOT (IpAddress="127.0.0.1" OR IpAddress="-")
| stats count by SubjectUserName, IpAddress, WorkstationName
| where count > 0
| sort -count
```
**ATT&CK:** T1550.002 — Pass the Hash

### Remote Service Execution (PsExec / WMI)
```spl
index=windows_logs (EventCode=7045 OR EventCode=4688)
| where match(ServiceFileName, "(?i)(psexec|paexec|wmic|winrm|sc\.exe)")
| table _time, ComputerName, ServiceFileName, AccountName
```
**ATT&CK:** T1021.002, T1047 — Remote Services

### Abnormal RDP Connections
```spl
index=windows_logs EventCode=4624 LogonType=10
| stats dc(ComputerName) as unique_targets, values(ComputerName) as targets by SubjectUserName, IpAddress
| where unique_targets > 3
```
**ATT&CK:** T1021.001 — Remote Desktop Protocol

---

## 4. Privilege Escalation

### New Local Admin Account Created
```spl
index=windows_logs EventCode=4720 OR EventCode=4732
| where Group_Name="Administrators" OR TargetUserName="Administrators"
| table _time, SubjectUserName, TargetUserName, ComputerName
```
**ATT&CK:** T1136.001 — Create Account: Local Account

### Scheduled Task Created by Non-Admin
```spl
index=windows_logs EventCode=4698
| where NOT match(SubjectUserName, "(?i)(admin|system|svc_)")
| table _time, SubjectUserName, TaskName, TaskContent, ComputerName
```
**ATT&CK:** T1053.005 — Scheduled Task/Job

---

## 5. Data Exfiltration

### Large DNS Query Volume (DNS Tunneling)
```spl
index=dns_logs
| stats count by src_ip, query
| where count > 200
| rex field=query "(?<domain>[^.]+\.[^.]+)$"
| stats sum(count) as total_queries, dc(query) as unique_subdomains by src_ip, domain
| where unique_subdomains > 50
```
**ATT&CK:** T1071.004 — DNS Tunneling

### Outbound Data to Rare Countries
```spl
index=proxy_logs
| iplocation dest_ip
| where NOT Country IN ("United States","United Kingdom","Canada","Australia")
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip, Country, url
| where total_bytes > 10000000
| sort -total_bytes
```
**ATT&CK:** T1041 — Exfiltration Over C2 Channel

---

## 6. Malware & C2

### PowerShell Encoded Command Execution
```spl
index=windows_logs EventCode=4688 (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*-e *")
| where match(CommandLine, "(?i)powershell")
| table _time, ComputerName, AccountName, CommandLine
```
**ATT&CK:** T1059.001 — PowerShell

### Beacon-like Periodic Outbound Connections
```spl
index=firewall_logs action=allowed
| bucket _time span=1m
| stats count by src_ip, dest_ip, dest_port, _time
| eventstats avg(count) as avg_count, stdev(count) as stdev_count by src_ip, dest_ip
| where stdev_count < 2 AND avg_count > 1
| stats count as beacon_minutes by src_ip, dest_ip, dest_port
| where beacon_minutes > 20
```
**ATT&CK:** T1071 — Application Layer Protocol (C2 beaconing)

---

## Dashboard Accelerators

### Top 10 Noisy Sources (Last 24h)
```spl
index=* earliest=-24h
| stats count by host, sourcetype
| sort -count
| head 10
```

### Alert Volume Trend by Severity
```spl
index=alerts earliest=-7d
| timechart span=1d count by severity
```
