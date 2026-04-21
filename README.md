# Securacy Security QA Assessment Submission

## Repository Purpose

This repository contains my submission for the Security QA assessment for a cloud hosted food delivery platform on Azure. The objective of this submission is to demonstrate practical security testing capability, structured documentation, repeatable test design, and awareness of regulatory and compliance requirements.

The submission focuses on two core threats:

* T003: Authorization, Privilege Escalation, RBAC, ABAC, IDOR
* T004: API Rate Limiting, Throttling, Abuse Protection, Resilience

It also includes bonus tasks covering risk prioritisation, automation, false positive analysis, and compliance mapping.

---

## Repository Structure

```text
.
├── README.md
├── T003_test_spec.md
├── T004_test_spec.md
├── scripts/
│   └── rate_limit_test.py
├── Risk_Matrix.md
├── False_Positive_Analysis.md
└── Compliance_Mapping.md
```

---

## File Descriptions

### README.md

Overview of the repository, contents, prerequisites, and execution guidance.

### T003_test_spec.md

Security test specification for authorization controls including RBAC, ABAC, privilege escalation prevention, ownership checks, and JWT validation.

### T004_test_spec.md

Security test specification for API rate limiting, throttling controls, brute force protection, and circuit breaker resilience.

### scripts/bonus_task_2_rate_limit_test.py

Python automation script that validates the 101st authentication request is throttled and verifies Retry-After header behaviour.

### Bonus_Task_1_Risk_Matrix.md

Prioritised threat matrix using CVSS scoring and business impact analysis.

### Bonus_Task_3_False_Positive_Analysis.md

WAF over-blocking analysis with legitimate input scenarios, rule references, and recommended exclusions.

### Bonus_Task_4_Compliance_Mapping.md

Mapping of threats and mitigations to PCI-DSS v4.0, GDPR, and SOC 2 control objectives.

---

## Prerequisites

The following tools may be required to execute the included commands and scripts:

* Python 3.x
* requests Python library
* curl
* jq
* Git
* Access to a valid target BASE_URL
* Optional: vegeta for load testing scenarios

Install Python dependency:

```bash
pip install requests
```

---

## How to Run the Automated Test Script

Update the BASE_URL value inside:

```text
scripts/rate_limit_test.py
```

Run:

```bash
python scripts/rate_limit_test.py
```

The script will:

* Send 101 authentication requests
* Validate that requests 1 to 100 are not throttled
* Validate request 101 returns HTTP 429
* Validate Retry-After header is present and numeric
* Print a final PASS or FAIL summary

---

## Security Testing Approach

This submission follows a repeatable QA methodology:

1. Define threat and expected control behaviour
2. Create positive, negative, and edge test cases
3. Provide executable commands
4. Define measurable pass criteria
5. Validate audit evidence in logs
6. Map controls to compliance obligations

---

## Compliance Scope Covered

The submission references controls from:

* PCI-DSS v4.0
* GDPR
* SOC 2

These mappings are included to demonstrate how security testing supports audit readiness and governance objectives.

---

## Author

Submitted by: Amrutha V R
