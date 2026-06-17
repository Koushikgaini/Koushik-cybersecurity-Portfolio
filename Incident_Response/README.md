# Incident Response Projects

Playbooks, timelines, and checklists for structured incident response across common attack scenarios.

## Contents

| File | Description |
|------|-------------|
| [ransomware_playbook.md](./ransomware_playbook.md) | End-to-end ransomware IR playbook (detection → recovery) |
| [breach_response_timeline.md](./breach_response_timeline.md) | Breach notification timeline with GDPR/HIPAA windows |
| [ir_checklist.md](./ir_checklist.md) | First-responder checklist for any incident type |

## IR Phases (NIST SP 800-61r2)

```
Preparation → Detection & Analysis → Containment → Eradication → Recovery → Post-Incident
```

## Severity Classification

| Severity | Definition | Example |
|----------|-----------|---------|
| P1 — Critical | Active breach, data exfil in progress, ransomware spreading | Active C2, encryption in progress |
| P2 — High | Confirmed compromise, contained | Isolated host with malware |
| P3 — Medium | Suspicious activity, unconfirmed | Anomalous login, possible phishing |
| P4 — Low | Policy violation, no malicious intent | Unauthorized software install |
