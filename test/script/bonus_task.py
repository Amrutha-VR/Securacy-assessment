
| Threat | CVSS v3.1 | Business Impact | Priority |
|---|---|---|---|
| Broken Authentication | 9.1 | High — account takeover exposes saved cards, addresses, live driver GPS | 1 |
| IDOR / BOLA | 8.8 | High — predictable order IDs leak names, phones, receipts across tenants | 2 |
| Injection | 8.6 | High — DB compromise exposes all customers, restaurants, payout records | 3 |
| Data Leakage | 8.2 | High — GDPR fines up to 4% global turnover, reputational damage | 4 |
| Misconfiguration | 8.0 | High — open storage accounts, exposed APIM keys, public blobs | 5 |
| Rate Limiting Absent | 7.8 | Medium/High — enables carding fraud, scraping, mealtime DDoS | 6 |
| SSRF | 7.5 | Medium/High — Azure IMDS metadata access, internal service pivoting | 7 |
| Supply Chain | 7.4 | High — compromised npm/pip package affects all deployments | 8 |
| Insider Threat | 7.2 | High — privileged DB access, bulk export of customer PII | 9 |
| Excessive Data Exposure | 6.9 | Medium — API responses returning unnecessary PII fields | 10 |

**Fix First Justification**

**1. Broken Authentication (Priority 1)** must be remediated first because a compromised customer or admin account immediately unlocks saved payment cards, full order history, home addresses, and real-time driver locations. On a food delivery platform this means direct financial fraud, stalking risk via delivery address exposure, and loyalty balance theft. This maps directly to PCI-DSS v4.0 Req 8.3.6 (strong authentication factors), Req 8.6.3 (brute force protection), and Req 10.2.1.b (logging of authentication failures) — all of which are assessed during a PCI audit.

**2. IDOR / BOLA (Priority 2)** is structurally dangerous because food delivery platforms assign sequential or guessable order IDs, meaning a single valid session token can be used to enumerate every customer's name, phone number, delivery address, receipt, and assigned driver across the entire platform. This constitutes a mass personal data breach under GDPR Art. 4(12) with mandatory 72-hour notification to supervisory authorities under Art. 33, and triggers PCI-DSS Req 7.2.5 (least privilege by role) and Req 12.10.2 (breach response obligations).

**3. Injection (Priority 3)** can compromise the entire ordering database in a single attack, including customer PII, restaurant financial data, delivery partner records, and payment references. On a food delivery platform, a successful injection during peak mealtime results in both an immediate data breach and operational outage — maximising both regulatory exposure (GDPR Art. 32, PCI-DSS Req 6.2.4 secure coding, Req 11.4.7 WAF protections) and business impact through lost revenue, refund obligations, and reputational damage.

For a food delivery platform specifically, these three threats converge around the same assets — customer personal data including home addresses, saved payment methods, and real-time location — making their combined exploitation both trivially achievable and maximally harmful.

---

# Bonus Task 2 — Automated Test Script (TC-004-02)

```python
import requests
import time
from collections import Counter
from datetime import datetime

# ── Configuration ─────────────────────────────────────────────────────────────
BASE_URL = "https://foodapp.example.com"
LOGIN_PATH = "/api/auth/login"
TOTAL_REQUESTS = 101
REQUEST_DELAY_SECONDS = 0.5   # ~50s total — fits within the 60s window
TIMEOUT = 5
# ──────────────────────────────────────────────────────────────────────────────

URL = BASE_URL + LOGIN_PATH
results = []
errors = []
retry_after_value = None

print("=" * 60)
print("TC-004-02 — Rate Limit Enforcement Validation")
print(f"Target : {URL}")
print(f"Total  : {TOTAL_REQUESTS} requests @ {REQUEST_DELAY_SECONDS}s intervals")
print(f"Started: {datetime.utcnow().isoformat()}Z")
print("=" * 60)

for i in range(1, TOTAL_REQUESTS + 1):
    try:
        resp = requests.post(
            URL,
            json={"username": "invalid", "password": "invalid"},
            timeout=TIMEOUT
        )
        code = resp.status_code
        results.append(code)

        # Capture Retry-After from the first 429 response
        if code == 429 and retry_after_value is None:
            retry_after_value = resp.headers.get("Retry-After")
            print(f"Request {i:03d}: {code}  <-- THROTTLED | Retry-After: {retry_after_value}")
        else:
            print(f"Request {i:03d}: {code}")

        time.sleep(REQUEST_DELAY_SECONDS)

    except Exception as ex:
        results.append("ERR")
        errors.append(str(ex))
        print(f"Request {i:03d}: ERROR — {ex}")

# ── Assertions ────────────────────────────────────────────────────────────────
counts = Counter(results)

# Assertion A: No 429 in the first 100 requests
first_100 = results[:100]
assertion_a = (429 not in first_100)

# Assertion B: Request 101 returns 429
assertion_b = (len(results) >= 101 and results[100] == 429)

# Assertion C: Retry-After is a positive integer
if retry_after_value is not None:
    assertion_c = str(retry_after_value).strip().isdigit() and int(retry_after_value) > 0
else:
    assertion_c = False

all_passed = assertion_a and assertion_b and assertion_c

# ── Summary ───────────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print(f"Total requests sent : {len(results)}")
print(f"Network errors      : {len(errors)}")
print("")
print("Response code breakdown:")
for code, count in sorted(counts.items(), key=lambda x: str(x[0])):
    print(f"  {code}: {count}")
print("")
print(f"Assertion A — Requests 1-100 never throttled : {'PASS' if assertion_a else 'FAIL'}")
print(f"Assertion B — Request 101 returns 429        : {'PASS' if assertion_b else 'FAIL'}")
print(f"Assertion C — Retry-After is positive int    : {'PASS' if assertion_c else 'FAIL'}")
print(f"Retry-After value captured                   : {retry_after_value}")
print("")
print("=" * 60)
print("FINAL RESULT:", "PASS" if all_passed else "FAIL")
print("=" * 60)
```

---

# Bonus Task 3 — False Positive Analysis (WAF Over-Blocking)

## FP-001 — Restaurant name containing an apostrophe must not be blocked

**Scenario:** A restaurant operator onboards their business with the legal name "McDonald's" or "O'Brien's Kitchen". The WAF must allow this input.

**Steps**

1. Authenticate as `admin01` to obtain an Admin JWT.
2. Send a POST to `/api/restaurants` with a restaurant name containing a single apostrophe.
3. Record the HTTP status code. Expected: `201 Created`. A `403 Forbidden` indicates WAF over-blocking.
4. If blocked, check APIM WAF logs for the triggering rule ID.

**Tools/Commands**

```bash
# Step 1 — Obtain Admin JWT
TOKEN=$(curl -s -X POST "https://foodapp.example.com/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "grant_type=password&username=admin01&password=AdminPass!23&scope=api.read" \
  | jq -r '.access_token')

# Step 2 — POST restaurant with apostrophe in name
curl -i -X POST "https://foodapp.example.com/api/restaurants" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"McDonald'\''s","address":"123 High St"}'
```

**Expected Result:** `HTTP 201 Created`

**Pass Criteria:** Response is 201. No WAF block. Restaurant record created successfully.

**Potentially Triggered WAF Rule:** OWASP CRS Rule **942130** — *SQL Injection Attack Detected via libinjection*. This rule flags single-quote characters as potential SQL injection delimiters. An apostrophe in a business name is a common punctuation character and is not malicious when the backend uses parameterized queries. The input never reaches SQL directly — it is validated against a JSON schema, length-checked, and stored via an ORM with bound parameters.

**Recommended WAF Exclusion:** Apply a targeted exclusion for CRS rule 942130 scoped to the `name` field on `POST /api/restaurants`, only for authenticated requests bearing a valid Admin JWT. Do not disable the rule globally. Document the exclusion in the WAF change log for PCI audit evidence.

---

## FP-002 — Menu item price with currency symbol and comma must not be blocked

**Scenario:** A restaurant lists a menu item priced at "₹1,299.00" or "$9.99". The WAF must allow standard currency formatting.

**Steps**

1. Authenticate as `admin01` to obtain an Admin JWT.
2. Send a POST to `/api/menu-items` with a price field containing a currency symbol, comma, and decimal point.
3. Record the HTTP status code. Expected: `201 Created`. A `403 Forbidden` indicates WAF over-blocking.
4. If blocked, check APIM WAF logs for the triggering rule ID.

**Tools/Commands**

```bash
# Step 1 — Obtain Admin JWT (reuse from FP-001 if in same session)
TOKEN=$(curl -s -X POST "https://foodapp.example.com/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "grant_type=password&username=admin01&password=AdminPass!23&scope=api.read" \
  | jq -r '.access_token')

# Step 2 — POST menu item with currency-formatted price
curl -i -X POST "https://foodapp.example.com/api/menu-items" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Paneer Butter Masala","price":"₹1,299.00","category":"mains"}'
```

**Expected Result:** `HTTP 201 Created`

**Pass Criteria:** Response is 201. No WAF block. Menu item created with price value intact.

**Potentially Triggered WAF Rule:** OWASP CRS Rule **942430** — *Restricted SQL Character Anomaly Detection*. This rule scores sequences of special characters (commas, currency symbols, periods in combination) as potential SQL character injection. Currency formatting is standard commercial input for a multi-currency food platform serving Indian, US, and European markets. The price field is validated server-side against a regex accepting `[£$€₹]?[\d,]+\.?\d{0,2}` before any database interaction.

**Recommended WAF Exclusion:** Apply a targeted exclusion for CRS rule 942430 scoped to the `price` field on `POST /api/menu-items` only for authenticated Admin and RestaurantAdmin requests. Enforce server-side regex validation as a compensating control and document the exclusion in the WAF change log.

---

# Bonus Task 4 — Compliance Mapping Table

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
