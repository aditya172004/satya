# Incident Response Workflow (SOP)

## Purpose
Quick guide for SOC analysts to triage, escalate, and remediate security incidents.

## Definitions
- Incident Severity: Low / Medium / High / Critical
- Incident Types: Malware, Data Exfiltration, DDoS, Brute Force, etc.

## Detection & Triage
1. Alert received (automated or manual).
2. Triage steps:
   - Identify source IP / user / asset
   - Confirm indicator (log evidence, model score)
   - Check enrichment (ThreatFeed: AbuseIPDB / VT / OTX)
   - Assign preliminary severity

## Containment
- Short-term actions: block IP, disable user account, isolate host
- Long-term: snapshots, forensics imaging

## Eradication & Recovery
- Remove malicious artifacts, patch vulnerabilities, restore services from known-good backups

## Communication & Reporting
- Internal: Notify SOC lead, system owner
- External: Notify legal / communications as required

## Post-Incident
- Root cause analysis
- Update detection rules & playbooks
- Archive incident report (store in ticketing/KB)

## Roles & Responsibilities
- SOC Analyst: triage, initial containment
- SOC Lead: escalate decisions, coordinate stakeholders
- Forensics Team: deep-dive investigation
- IT Ops: remediate systems & restore service

## Playbooks / Runbooks (examples)
- Ransomware suspected
- Phishing detected
- Data exfiltration

