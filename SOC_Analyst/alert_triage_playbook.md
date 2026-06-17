# SOC Alert Triage Playbook

Standard operating procedure for Level 1/2 SOC analysts triaging incoming SIEM alerts.

---

## Phase 1: Initial Alert Review (< 5 minutes)

1. **Read the alert title and severity** — note the assigned priority (P1–P4).
2. **Identify the affected asset** — hostname, IP, username, department.
3. **Check asset criticality** — is this a domain controller, database server, executive endpoint?
4. **Review the raw log/event** — understand *exactly* what triggered the rule.
5. **Check for duplicates** — is this a recurring alert for the same asset? Is it already in an open ticket?

**Decision gate:** Is this an obvious false positive (scheduled scan, known maintenance, whitelisted tool)?
- YES → Document reason, close ticket with `FP — [reason]`, update whitelist if appropriate.
- NO → Proceed to Phase 2.

---

## Phase 2: Context Enrichment (5–15 minutes)

### IP / Domain Enrichment
- Query threat intel feeds: VirusTotal, AbuseIPDB, Shodan, Talos Intelligence
- Check internal SIEM for historical activity from the same IP/domain
- Look up geolocation — unexpected country?

### User Context
- Is the account a service account or human user?
- Check AD/LDAP: last login, group memberships, recent password changes
- Review recent ticket history for this user (Jira/ServiceNow)
- HR verify: is the user currently employed, on leave, or terminated?

### Endpoint Context
- EDR (CrowdStrike/Defender): process tree, parent process, file hash, network connections
- Check if endpoint has recent vulnerability scan findings
- Is the host in a sensitive network segment (PCI, HIPAA, OT)?

### Timeline Correlation
```
T-00:00  Alert fires
T-xx:xx  Look 30 min before → what happened just before?
T+xx:xx  Look 30 min after  → did behavior continue / spread?
```

---

## Phase 3: Threat Classification

| Verdict | Definition | Action |
|---------|-----------|--------|
| **True Positive** | Confirmed malicious activity | Escalate per severity; begin containment |
| **True Positive — Benign** | Real behavior, not malicious (pen test, authorized scan) | Document authorization, close, add exception |
| **False Positive** | Alert rule fired incorrectly | Document, close, tune rule if recurring |
| **Indeterminate** | Cannot confirm or deny | Escalate to L2/L3 with full context |

---

## Phase 4: Escalation Decision Tree

```
Is this a CONFIRMED compromise (shell, C2, active exfil)?
├── YES → P1: Page on-call IR lead NOW. Do not wait.
└── NO
    Is there lateral movement or privilege escalation?
    ├── YES → P2: Escalate to IR team within 1 hour.
    └── NO
        Is malware confirmed on endpoint?
        ├── YES → P2: Isolate host, escalate to L2.
        └── NO
            Is this suspicious but unconfirmed?
            ├── YES → P3: Document findings, enrich further, monitor.
            └── NO → P4: Low priority, log and monitor.
```

---

## Phase 5: Documentation Standards

Every ticket must include:

```
TICKET: [SIEM-XXXX]
Analyst: [Name]
Date/Time: [UTC]
Alert: [Alert name and rule ID]

AFFECTED ASSETS:
  - Host: [hostname / IP]
  - User: [username / department]
  - Asset Criticality: [Low / Medium / High / Critical]

SUMMARY:
  [1-3 sentence description of what the alert detected]

EVIDENCE:
  - [Log line 1]
  - [Log line 2]
  - [Threat intel findings]

VERDICT: [True Positive / False Positive / Indeterminate]
SEVERITY: [P1 / P2 / P3 / P4]

ACTIONS TAKEN:
  - [Step 1]
  - [Step 2]

DISPOSITION: [Escalated / Closed / Monitoring]
MITRE ATT&CK: [Tactic — Technique ID]
```

---

## Common False Positive Patterns

| Alert Type | Common FP Cause | Resolution |
|-----------|----------------|------------|
| Port scan detected | Nessus/Qualys scheduled scan | Verify scan schedule, whitelist scanner IP |
| Admin tool usage | IT helpdesk remote support | Confirm with helpdesk ticket |
| Large file transfer | Authorized backup job | Check backup schedule, whitelist job |
| Off-hours login | Traveling employee, timezone | Confirm with HR/manager |
| Suspicious PowerShell | SCCM/Ansible automation | Check deployment logs |
