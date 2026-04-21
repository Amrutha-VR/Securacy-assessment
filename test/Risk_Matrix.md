# Risk Prioritisation Matrix

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

**1. Broken Authentication (Priority 1)** must be remediated first because a compromised customer or admin account immediately unlocks saved payment cards, full order history, home addresses, and real-time driver locations. On a food delivery platform this means direct financial fraud, stalking risk via delivery address exposure, and loyalty balance theft. This maps directly to PCI-DSS v4.0 Req 8.3.6 (strong authentication factors), Req 8.6.3 (brute force protection), and Req 10.2.1.b (logging of authentication failures) all of which are assessed during a PCI audit.

**2. IDOR / BOLA (Priority 2)** is structurally dangerous because food delivery platforms assign sequential or guessable order IDs, meaning a single valid session token can be used to enumerate every customer's name, phone number, delivery address, receipt, and assigned driver across the entire platform. This constitutes a mass personal data breach under GDPR Art. 4(12) with mandatory 72-hour notification to supervisory authorities under Art. 33, and triggers PCI-DSS Req 7.2.5 (least privilege by role) and Req 12.10.2 (breach response obligations).

**3. Injection (Priority 3)** can compromise the entire ordering database in a single attack, including customer PII, restaurant financial data, delivery partner records, and payment references. On a food delivery platform, a successful injection during peak mealtime results in both an immediate data breach and operational outage maximising both regulatory exposure (GDPR Art. 32, PCI-DSS Req 6.2.4 secure coding, Req 11.4.7 WAF protections) and business impact through lost revenue, refund obligations, and reputational damage.

For a food delivery platform specifically, these three threats converge around the same assets  customer personal data including home addresses, saved payment methods, and real-time location making their combined exploitation both trivially achievable and maximally harmful.

---
