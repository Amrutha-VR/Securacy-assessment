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
