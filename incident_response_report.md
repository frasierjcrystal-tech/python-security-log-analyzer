# Incident Response Report

## Executive Summary

A review of the authentication logs identified multiple failed login attempts involving several user accounts. The highest concentration of failures targeted the **guest** account, suggesting possible password guessing or brute-force activity.

---

## Investigation Findings

- Total failed login attempts detected: **7**
- Multiple failed attempts for the same usernames
- Successful logins observed after several failed attempts
- No evidence of privilege escalation

---

## Affected Accounts

- guest
- root
- admin
- test

---

## Indicators of Compromise (IOCs)

- Multiple failed login attempts
- Repeated authentication failures
- Suspicious login patterns

---

## Risk Assessment

| Risk | Severity |
|-------|----------|
| Brute-force attack | High |
| Credential guessing | Medium |
| Unauthorized access | Medium |

---

## Recommended Actions

- Enable Multi-Factor Authentication (MFA)
- Lock accounts after repeated failed logins
- Monitor authentication logs continuously
- Review privileged account activity
- Implement SIEM alerting

---

## Lessons Learned

Authentication logs provide valuable insight into suspicious behavior. Continuous monitoring, proactive alerting, and routine log analysis reduce the likelihood of successful unauthorized access.

---

**Prepared by**

**Crystal Frasier**

Founder — Quantum Technologies

Cybersecurity • Artificial Intelligence • Risk Analysis
