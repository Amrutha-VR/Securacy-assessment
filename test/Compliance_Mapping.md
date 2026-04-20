# Compliance Mapping Table

| Threat ID | Mitigation | PCI-DSS v4.0 Req | GDPR Article | SOC 2 Control | Why this test evidences the clause |
|---|---|---|---|---|---|
| T001 Broken Auth | MFA + account lockout | Req 8.3.6, 8.6.3 | Art. 32(1)(b) | CC6.1 | Test confirms authentication brute-force is blocked and MFA is enforced, directly satisfying the strong authentication and anti-automation requirements |
| T002 Excessive Data Exposure | Response field filtering | Req 3.4.2 | Art. 5(1)(c) | CC6.7 | Test confirms API responses return only the minimum data fields necessary, evidencing data minimisation and cardholder data masking obligations |
| T003 IDOR / AuthZ | RBAC + ABAC + JWT validation | Req 7.2.5, 3.3.1 | Art. 25, 32(1)(b) | CC6.1 | Tests confirm role and ownership checks block cross-user access and privilege escalation, directly evidencing least-privilege and privacy-by-design controls |
| T004 Rate Limiting | APIM tiered throttling + circuit breaker | Req 6.4.2, 8.6.3 | Art. 32(1)(b) | CC7.1 | Tests confirm automated attack protections are active on auth and payment endpoints, evidencing anti-carding and anti-stuffing controls required by PCI |
| T005 Injection | Parameterised queries + WAF | Req 6.2.4, 11.4.7 | Art. 32(1)(a) | CC7.2 | Test confirms malicious SQL/command injection payloads are rejected at the WAF and application layer, satisfying secure coding and web application protection requirements |
| T006 Misconfiguration | Security baseline + IaC scanning | Req 2.2.1 | Art. 24 | CC8.1 | Test confirms deployed infrastructure matches approved secure baseline, evidencing configuration management and controller accountability obligations |
| T007 SSRF | Egress firewall + metadata endpoint blocking | Req 1.3.2 | Art. 32(1)(b) | CC7.1 | Test confirms internal Azure metadata endpoints (169.254.169.254) and private subnets are unreachable from application context, satisfying network segmentation requirements |
| T008 Supply Chain | Dependency vulnerability scanning (Dependabot/Snyk) | Req 6.3.2 | Art. 32(1)(a) | CC8.1 | Test confirms third-party packages have no known critical CVEs at deployment time, evidencing software composition analysis obligations |
| T009 Insider Threat | PAM + privileged session logging | Req 7.1.1, 10.2.1 | Art. 29 | CC6.3 | Test confirms privileged access requires approval workflow and all admin sessions are logged with full audit trail, satisfying processor accountability and access control obligations |
| T010 Data Leakage | Encryption at rest + in transit + DLP policy | Req 3.5.1, 4.2.1 | Art. 32(1)(a) | CC6.7 | Test confirms PII and cardholder data is encrypted in storage and transit, and DLP rules block exfiltration via email or API, evidencing technical security measure requirements |
