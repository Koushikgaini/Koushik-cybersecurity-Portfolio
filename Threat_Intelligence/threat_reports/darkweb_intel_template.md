# Dark Web Intelligence Monitoring Report

**Classification:** TLP:RED — Do not share outside organization  
**Report ID:** DWI-YYYY-XXXX  
**Monitoring Period:** YYYY-MM-DD to YYYY-MM-DD  
**Analyst:** [Name]  

> **Legal Notice:** Dark web monitoring is performed using passive collection tools and authorized third-party intelligence feeds only. No unauthorized access to criminal forums or markets was performed.

---

## Executive Summary

[1-2 sentence summary of findings — e.g., "No credential dumps or mention of [Organization] were found this period. One dark web forum post referencing [Industry] targeting was observed and tracked."]

**Overall Risk Posture:** 🟢 Low / 🟡 Medium / 🔴 High

---

## Monitoring Coverage

| Source Type | Tools / Feeds Used | Coverage |
|-------------|-------------------|---------|
| Dark web forums (paste sites) | Recorded Future, DarkOwl | Partial |
| Telegram threat actor channels | Threat intel feeds | Partial |
| Ransomware leak sites | Manual monitoring + RSS | Full |
| Breach/credential marketplaces | HaveIBeenPwned, IntelligenceX | Partial |
| GitHub/code repositories | GitGuardian, truffleHog | Full |

---

## Findings

### Finding 1: [Title — e.g., Corporate Email Credentials Listed for Sale]

**Severity:** Critical / High / Medium / Low  
**Source:** [Forum name / marketplace — do not link directly]  
**Date Observed:** YYYY-MM-DD  
**Confidence:** High / Medium / Low  

**Description:**  
[Detailed description of what was found. What data is exposed, what actor is claiming to sell/release it, what the ask price is if applicable.]

**Sample Evidence (Sanitized):**
```
[Paste/screenshot excerpt with PII redacted or hashed]
```

**Affected Data:**
- Email addresses: ~X records
- Passwords: [Hashed / Plaintext / Unknown]
- Additional PII: [Names, phone numbers, etc.]

**Actor Notes:**  
[Any information about the threat actor posting this — reputation, history, claims vs. reality]

**Recommended Actions:**
1. Force password reset for all affected accounts
2. Check login history for affected users for past 90 days
3. Alert affected individuals per breach notification policy
4. Engage legal/compliance team if PII is involved (GDPR/HIPAA timeline)

---

### Finding 2: [e.g., Organization Named as Ransomware Target on Forum]

**Severity:** High  
**Source:** [Threat actor forum — name only, no URL]  
**Date Observed:** YYYY-MM-DD  

**Description:**  
[Threat actor claiming to have access or planning to target the organization. Include specifics if available.]

**Recommended Actions:**
1. Review firewall/VPN logs for unusual external access
2. Check for exposed RDP, VPN without MFA
3. Threat hunt for indicators of pre-ransomware reconnaissance (T1082, T1046)

---

## Credential Exposure Summary

| Domain | Records Found | Source | Date | Status |
|--------|--------------|--------|------|--------|
| company.com | 0 | — | — | Clean |
| subsidiary.com | 14 | BreachForum post | YYYY-MM-DD | Investigating |

---

## Ransomware Leak Site Monitoring

| Group | Active? | Recent Victims | Industry Focus | Relevance |
|-------|---------|---------------|---------------|---------|
| LockBit 3.0 | Active | [n] this month | Manufacturing, Healthcare | Monitor |
| BlackCat/ALPHV | Inactive | Dismantled | Financial | Low |
| Cl0p | Active | [n] this month | Retail, Education | Monitor |
| Play | Active | [n] this month | Local Govt, Legal | Low |

---

## Recommended Monitoring Keywords

Maintain automated alerting for:

```
"[Organization name]"
"[Domain name]"
"[Key executive names]"
"[Product names]"
"[IP ranges / CIDRs]"
"[Subsidiary company names]"
```

---

## Action Items Tracker

| Action | Owner | Due Date | Status |
|--------|-------|----------|--------|
| Reset passwords for exposed accounts | Identity team | YYYY-MM-DD | Open |
| Notify affected users | Legal/HR | YYYY-MM-DD | Open |
| Add new IOCs to SIEM blocklist | SOC | YYYY-MM-DD | Open |
| Submit report to ISAC | Threat Intel | YYYY-MM-DD | Open |

---

## Appendix: Intelligence Tools Reference

| Tool | Use Case | License |
|------|---------|---------|
| HaveIBeenPwned API | Email/domain breach check | Free + Paid |
| IntelligenceX | Dark web search | Paid |
| Recorded Future | Automated dark web monitoring | Enterprise |
| DarkOwl Vision | Dark web corpus search | Enterprise |
| GitGuardian | Code/secret exposure in repos | Free + Paid |
| Shodan | Internet-exposed asset discovery | Free + Paid |
