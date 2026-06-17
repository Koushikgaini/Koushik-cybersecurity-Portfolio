# Breach Response Timeline

Templates and regulatory notification windows for data breach response under GDPR, HIPAA, and US state laws.

---

## Regulatory Notification Windows

| Regulation | Notification To | Deadline | Trigger |
|-----------|----------------|---------|---------|
| **GDPR** (EU) | Supervisory Authority | **72 hours** from discovery | Any personal data breach |
| **GDPR** (EU) | Affected Individuals | Without undue delay | High-risk breaches only |
| **HIPAA** (US) | HHS (OCR) | **60 days** from discovery | Any PHI breach ≥ 500 individuals |
| **HIPAA** (US) | Affected Individuals | **60 days** from discovery | Any PHI breach |
| **HIPAA** (US) | Local media | **60 days** from discovery | PHI breach ≥ 500 in state |
| **PCI DSS** | Card brands & acquirer | **24 hours** | Any PAN data compromise |
| **California (CCPA)** | Individuals | "Expedient" | PII breach |
| **NY SHIELD Act** | NY AG | Expedient | PII breach of NY residents |
| **SEC Rule** (public co.) | SEC Form 8-K | **4 business days** | Material cybersecurity incident |

---

## Breach Response Timeline Template

### Hour 0 — Discovery

```
[ ] Alert detected / breach reported
[ ] Incident ticket created (severity P1/P2)
[ ] Incident Commander paged
[ ] Initial scope assessment started
[ ] Evidence preservation begins (DO NOT wipe systems)
[ ] Legal counsel notified
[ ] Clock starts for regulatory deadlines
```

**Key questions at Hour 0:**
- What data may have been accessed? (PII, PHI, PAN, credentials, IP)
- How many individuals are potentially affected?
- What time did the breach begin vs. when was it discovered?
- Is the breach ongoing?

---

### Hour 1–4 — Initial Assessment

```
[ ] Affected systems identified and isolated
[ ] Data types confirmed (PII / PHI / PAN / credentials / other)
[ ] Approximate number of affected records estimated
[ ] Forensic investigation initiated
[ ] Executive team briefed
[ ] Regulatory obligations reviewed with legal
[ ] PR/Communications team put on standby
```

**Decision: Does this breach require mandatory notification?**

```
Does the breach involve:
├── EU resident personal data? → GDPR 72-hour clock running
├── Protected Health Information (PHI)? → HIPAA 60-day clock running
├── Payment card data (PAN/CVV)? → PCI DSS 24-hour clock running
└── State-regulated PII? → Check applicable state law
```

---

### Hour 4–24 — Containment & Evidence Collection

```
[ ] Breach fully contained (or timeline for containment confirmed)
[ ] Forensic evidence collected and preserved
[ ] Attack vector identified (or investigation underway)
[ ] Full list of affected data records/individuals being compiled
[ ] Legal hold placed on relevant systems and logs
[ ] Cyber insurance carrier notified (check policy for 24-72h window)
[ ] Law enforcement contact decision made (FBI, CISA, Secret Service)
```

---

### Day 1–3 — Investigation & Regulatory Preparation

```
[ ] Root cause analysis underway
[ ] Affected individual list finalized (or best estimate)
[ ] GDPR notification drafted (72-hour deadline approaching)
[ ] Data types confirmed by forensic analysis
[ ] "Risk to individuals" assessment completed (GDPR Article 33)
[ ] Regulatory notification submitted (GDPR ≤ 72h from discovery)
[ ] Law enforcement report filed (if applicable)
```

**GDPR Notification to Supervisory Authority must include:**
1. Nature of the breach (categories and approximate number of individuals)
2. Name and contact of Data Protection Officer
3. Likely consequences of the breach
4. Measures taken or proposed to address the breach

---

### Day 3–7 — Remediation & Secondary Notifications

```
[ ] Affected systems remediated / rebuilt
[ ] Security controls reviewed and enhanced
[ ] Affected individuals notified (if high risk — GDPR; or required — HIPAA/state)
[ ] Credit monitoring offered (if financial data involved)
[ ] Dedicated breach hotline established (for large-scale breaches)
[ ] Press statement drafted and reviewed by legal
[ ] FAQ prepared for customer service team
```

---

### Day 7–30 — Ongoing Response

```
[ ] HIPAA breach notification submitted to HHS (within 60 days)
[ ] State AG notifications filed (as required)
[ ] Affected individuals notified (HIPAA, state law timelines)
[ ] Media notification (if > 500 HIPAA records in a state)
[ ] Board of Directors briefed
[ ] Insurance claim filed
[ ] Vendor/partner notifications (if third-party data affected)
```

---

### Day 30–90 — Closure & Reporting

```
[ ] All regulatory notifications completed
[ ] Post-incident review completed (see IR Playbook)
[ ] Annual breach report prepared (if required)
[ ] Security program improvements documented and tracked
[ ] Incident formally closed
[ ] Lessons learned published internally
[ ] Training updates identified based on root cause
```

---

## Breach Notification Letter Template

**Subject:** Important Security Notice

Dear [Individual Name],

We are writing to inform you that [Organization Name] recently discovered a security incident that may have affected your personal information.

**What Happened:**  
On [DATE], we discovered that [brief description of what occurred]. We immediately launched an investigation and took steps to contain the incident.

**What Information Was Involved:**  
The following types of personal information may have been accessed: [list data types].

**What We Are Doing:**  
We have taken the following steps: [list containment and remediation steps]. We have also [engaged cybersecurity experts / notified law enforcement / enhanced our security systems].

**What You Can Do:**  
We recommend that you:
- Monitor your financial accounts and credit reports for unusual activity
- Place a fraud alert or credit freeze with the major credit bureaus
- Be alert to phishing emails that may reference this incident
- [If applicable: We are providing 12 months of complimentary credit monitoring — instructions enclosed]

**For More Information:**  
If you have questions, please contact us at [HOTLINE / EMAIL] or visit [WEBSITE/BREACH-INFO].

We sincerely apologize for this incident and the concern it may cause.

Sincerely,  
[Name], [Title]  
[Organization Name]

---

## Regulatory Contact References

| Agency | Contact | Purpose |
|--------|---------|---------|
| HHS OCR | hhs.gov/hipaa/filing-a-complaint | HIPAA breach reporting |
| FTC | ftc.gov/databreach | FTC breach guidance |
| FBI IC3 | ic3.gov | Cybercrime reporting |
| CISA | cisa.gov/report | Critical infrastructure incidents |
| State AGs | Varies by state | State breach notification |
| EU DPAs | edpb.europa.eu/about-edpb/about-edpb/members | GDPR supervisory authorities |
