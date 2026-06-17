# SOC Analyst Projects

This section demonstrates real-world SOC analyst workflows: alert triage, Splunk detection queries, escalation decisions, and sample ticket documentation.

## Contents

| File | Description |
|------|-------------|
| [splunk_queries.md](./splunk_queries.md) | SPL query library for common attack patterns |
| [alert_triage_playbook.md](./alert_triage_playbook.md) | Step-by-step alert investigation workflow |
| [sample_tickets/phishing_alert.md](./sample_tickets/phishing_alert.md) | Simulated phishing alert ticket with analysis |
| [sample_tickets/brute_force_alert.md](./sample_tickets/brute_force_alert.md) | SSH brute force detection and response ticket |

## Alert Severity Matrix

| Priority | CVSS / Impact | Response SLA | Action |
|----------|--------------|--------------|--------|
| P1 — Critical | Active compromise / data exfil | 15 min | Immediate escalation, isolate host |
| P2 — High | Confirmed malware / C2 beacon | 1 hour | Escalate to IR team |
| P3 — Medium | Suspicious behavior, unconfirmed | 4 hours | Investigate, enrich, decide |
| P4 — Low | Policy violation / informational | 24 hours | Log, monitor, close if benign |
