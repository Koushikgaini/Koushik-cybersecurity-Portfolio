# Sample Ticket: SIEM-2024-0142 — Phishing Link Clicked by User

**Status:** Closed — True Positive (Benign Outcome)  
**Analyst:** Koushik Gaini  
**Date/Time:** 2024-03-14 09:47 UTC  
**SLA Target:** P3 — 4 hours  
**Resolution Time:** 1h 22m  

---

## Alert Details

**Alert Name:** `EDU-PHI-001 — User Clicked Known Phishing URL`  
**SIEM Rule ID:** `PHI-URL-CLICK-HIGH`  
**Source:** Proxy logs (Zscaler)  
**MITRE ATT&CK:** T1566.002 — Spearphishing Link

---

## Affected Assets

| Field | Value |
|-------|-------|
| User | jdoe@company.com (Jane Doe, Finance Dept) |
| Endpoint | CORP-WIN-0284 |
| Asset Criticality | Medium |
| Location | New York, NY (expected) |

---

## Raw Alert Evidence

```
[2024-03-14 09:43:11 UTC] PROXY BLOCK
  src_ip=10.22.4.84  user=jdoe@company.com
  url=http://secure-docusign-login[.]com/verify?token=a8f3bc
  category=Phishing  action=BLOCKED  bytes=0
  referrer=outlook://message/AAMkAGI3
```

**Threat Intel Results:**
- VirusTotal: 31/87 engines flagged as phishing (first seen 2024-03-13)
- URLhaus: Listed as active phishing kit targeting DocuSign credentials
- Domain age: 1 day (registered 2024-03-13 via Namecheap)

---

## Investigation Steps

**Step 1 — Confirm the block**  
Proxy logs confirmed the URL was blocked by Zscaler before any content was served. `bytes=0` — no page was loaded, no credentials were entered.

**Step 2 — Review email source**  
Retrieved email from Exchange audit logs:
```
From: notifications@docusign-secure[.]net
To: jdoe@company.com
Subject: Action Required: Sign Document Before Deadline
Received: 2024-03-14 09:41 UTC
Attachment: None | Links: 2 (one legitimate docusign.com, one phishing)
```
Email passed SPF/DKIM (spoofed from compromised legitimate domain). Sender domain `docusign-secure[.]net` registered 2 days prior.

**Step 3 — Endpoint review (CrowdStrike)**  
- No execution events following the click attempt
- No DNS resolution for the phishing domain (blocked at proxy before DNS)
- No persistence mechanisms, no unusual processes

**Step 4 — User interview**  
Contacted Jane Doe via Slack. She confirmed she received an email about a "pending contract" and clicked the link. The browser showed an error page (proxy block page). She did not enter any credentials.

---

## Verdict

**True Positive — No Compromise**  
The phishing email was delivered and the user clicked the link. However, the proxy block prevented any page load or credential submission. No endpoint compromise occurred.

---

## Actions Taken

1. **Email quarantined** — Submitted to Exchange admin to quarantine the email from all mailboxes company-wide.
2. **Domain blocked** — Added `docusign-secure[.]net` and `secure-docusign-login[.]com` to Zscaler blocklist.
3. **IOCs submitted** — Reported phishing domain to URLhaus and internal threat intel feed.
4. **User notified** — Sent security awareness reminder to Jane Doe with guidance on identifying phishing.
5. **Broad notification** — Sent phishing alert to all Finance department users (high-value targets).
6. **Email gateway rule** — Requested new rule to block emails with "DocuSign" in subject from external senders not originating from `docusign.com`.

---

## Disposition

**Closed** — True Positive, no compromise. IOCs logged. Preventive actions completed.

---

## Lessons Learned

- SPF/DKIM pass is not sufficient — look-alike domains can pass authentication checks.
- Finance department is a high-value phishing target (wire transfer fraud risk) — recommend additional training.
- Consider deploying DMARC enforcement monitoring for high-risk impersonated brands.
