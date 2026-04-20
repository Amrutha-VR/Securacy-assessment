## Threat Summary

Role-based permissions exist but enforcement is undocumented. This creates risk of Broken Object Level Authorization (BOLA/IDOR), Broken Function Level Authorization (BFLA), vertical privilege escalation, horizontal privilege escalation, and unauthorized access to sensitive payment or operational data. In a food delivery platform handling home addresses, live driver locations, and saved payment cards, any authorization gap creates immediate fraud and privacy exposure.

## Mitigation Summary

Implement defense-in-depth authorization controls: fine-grained RBAC mapped to business roles (Customer, DeliveryPartner, RestaurantAdmin, Admin, PaymentProcessor); ABAC using ownership, tenant, order state, geography, and assigned-delivery attributes; Azure API Management inbound policy enforcement; resource-level authorization checks in application code; signed JWT validation via Azure AD B2C; quarterly access reviews and role recertification; and centralized audit logging in Azure Monitor and Log Analytics.

## Pre-conditions

- Azure API Management fronts all APIs.
- Azure AD B2C issues signed JWT access tokens containing `roles` and `sub` claims.
- Test users provisioned: `customer01`, `customer02`, `delivery01`, `restaurant01`, `admin01`, `paymentsvc`.
- Sample data: order `1001` belongs to `customer01`, order `1002` belongs to `customer02`.
- Log Analytics workspace connected to APIM and App Services.
- Base URL: `https://foodapp.example.com`
- `jq` installed locally for JWT parsing.

---

## Test Cases

### TC-003-01

**Type:** Positive
**Title:** Admin can access admin-only endpoint with a valid Admin JWT

**Steps**

1. Send a POST to the token endpoint to obtain an Admin JWT for `admin01`. Extract the `access_token` field from the JSON response using `jq`.
2. Decode the JWT payload (base64 middle segment) and confirm the `roles` claim contains `"Admin"`.
3. Send a GET request to `/api/admin/users` with the Admin JWT in the `Authorization: Bearer` header.
4. Record the HTTP status code and confirm the response body contains user list data, not an error message.
5. Open Log Analytics and run the KQL query from Evidence to Collect. Confirm an `AuthorizationSuccess` event appears within 2 minutes with `principal = admin01` and `resource = /api/admin/users`.

**Tools/Commands**

```bash
# Step 1 — Obtain Admin JWT
TOKEN=$(curl -s -X POST "https://foodapp.example.com/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "grant_type=password&username=admin01&password=AdminPass!23&scope=api.read" \
  | jq -r '.access_token')

echo "JWT: $TOKEN"

# Step 2 — Decode and verify role claim
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '.roles'

# Step 3 — Call admin endpoint
curl -i -X GET "https://foodapp.example.com/api/admin/users" \
  -H "Authorization: Bearer $TOKEN"
```

**Expected Result**

- HTTP 200 OK
- Response body contains user list or admin data.

**Pass Criteria**

- JWT `roles` claim equals `Admin`.
- Response status is 200.
- No authorization error in body.

**Expected Log Entry**

- Event: `AuthorizationSuccess`
- Principal: `admin01`
- Resource: `/api/admin/users`
- Result: Allow

**Compliance**

- PCI-DSS v4.0 Req 7.2.5 — privileged access must be enforced to only authorized roles.

---

### TC-003-02

**Type:** Negative
**Title:** Customer attempts vertical escalation to Admin endpoint

**Steps**

1. Send a POST to the token endpoint to obtain a Customer JWT for `customer01`. Extract the `access_token` field from the JSON response.
2. Decode the JWT payload and confirm the `roles` claim contains `"Customer"` only — not `"Admin"`.
3. Send a GET request to `/api/admin/users` using the Customer JWT in the `Authorization: Bearer` header.
4. Record the HTTP status code and confirm the response body contains no admin data — only an error or empty body.
5. Open Log Analytics and run the KQL query from Evidence to Collect. Confirm an `AuthorizationDenied` event appears within 2 minutes with `principal = customer01` and `resource = /api/admin/users`.

**Tools/Commands**

```bash
# Step 1 — Obtain Customer JWT
TOKEN=$(curl -s -X POST "https://foodapp.example.com/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "grant_type=password&username=customer01&password=CustPass!23&scope=api.read" \
  | jq -r '.access_token')

# Step 2 — Confirm role claim
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '.roles'

# Step 3 — Attempt admin endpoint with Customer JWT
curl -i -X GET "https://foodapp.example.com/api/admin/users" \
  -H "Authorization: Bearer $TOKEN"
```

**Expected Result**

- HTTP 403 Forbidden

**Pass Criteria**

- Status code is 403.
- Response body contains no admin data.
- No role elevation occurs.

**Expected Log Entry**

- Event: `AuthorizationDenied`
- Principal: `customer01`
- Resource: `/api/admin/users`
- Result: Deny

**Compliance**

- SOC 2 CC6.1 — logical access restricted based on job function.

---

### TC-003-03

**Type:** Negative
**Title:** Customer attempts horizontal IDOR by changing order_id to another customer's order

**Steps**

1. Send a POST to the token endpoint to obtain a Customer JWT for `customer01`. Extract the `access_token` field.
2. Confirm that `customer01` owns order `1001` by successfully retrieving `GET /api/orders/1001`. This establishes a valid baseline.
3. Now send a GET request to `/api/orders/1002` (owned by `customer02`) using the same `customer01` JWT.
4. Record the HTTP status code. The system must return 403 Forbidden or 404 Not Found — never the order details.
5. Open Log Analytics and run the KQL query from Evidence to Collect. Confirm an `OwnershipCheckFailed` event appears within 2 minutes with `principal = customer01` and `resource = /api/orders/1002`.

**Tools/Commands**

```bash
# Step 1 — Obtain Customer01 JWT
TOKEN=$(curl -s -X POST "https://foodapp.example.com/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "grant_type=password&username=customer01&password=CustPass!23&scope=api.read" \
  | jq -r '.access_token')

# Step 2 — Confirm own order is accessible (baseline)
curl -i -X GET "https://foodapp.example.com/api/orders/1001" \
  -H "Authorization: Bearer $TOKEN"

# Step 3 — Attempt IDOR on another customer's order
curl -i -X GET "https://foodapp.example.com/api/orders/1002" \
  -H "Authorization: Bearer $TOKEN"
```

**Expected Result**

- Own order (1001): HTTP 200 OK
- Other customer's order (1002): HTTP 403 Forbidden or 404 Not Found

**Pass Criteria**

- Order `1002` details are never returned.
- Status is 403 or 404 on the IDOR attempt.

**Expected Log Entry**

- Event: `OwnershipCheckFailed`
- Principal: `customer01`
- Resource: `/api/orders/1002`
- Result: Deny

**Compliance**

- GDPR Art. 32(1)(b) — systems must ensure confidentiality and prevent unauthorized disclosure of personal data.

---

### TC-003-04

**Type:** Negative
**Title:** DeliveryPartner attempts to read restaurant financial data

**Steps**

1. Send a POST to the token endpoint to obtain a DeliveryPartner JWT for `delivery01`. Extract the `access_token` field.
2. Decode the JWT payload and confirm the `roles` claim contains `"DeliveryPartner"` only.
3. Send a GET request to `/api/restaurants/55/finance` using the DeliveryPartner JWT.
4. Record the HTTP status code and confirm no financial data (revenue, payouts, margins) is returned in the response body.
5. Open Log Analytics and run the KQL query from Evidence to Collect. Confirm an `AuthorizationDenied` event appears within 2 minutes with `principal = delivery01` and `resource = /api/restaurants/55/finance`.

**Tools/Commands**

```bash
# Step 1 — Obtain DeliveryPartner JWT
TOKEN=$(curl -s -X POST "https://foodapp.example.com/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "grant_type=password&username=delivery01&password=DelivPass!23&scope=api.read" \
  | jq -r '.access_token')

# Step 2 — Confirm role claim
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '.roles'

# Step 3 — Attempt to access financial endpoint
curl -i -X GET "https://foodapp.example.com/api/restaurants/55/finance" \
  -H "Authorization: Bearer $TOKEN"
```

**Expected Result**

- HTTP 403 Forbidden

**Pass Criteria**

- Status code is 403.
- No financial data exposed in response body.

**Expected Log Entry**

- Event: `AuthorizationDenied`
- Principal: `delivery01`
- Resource: `/api/restaurants/55/finance`
- Result: Deny

**Compliance**

- SOC 2 CC6.6 — sensitive financial information access is restricted to authorized roles only.

---

### TC-003-05

**Type:** Negative
**Title:** Admin attempts to directly retrieve raw payment card data (separation of duties)

**Steps**

1. Send a POST to the token endpoint to obtain an Admin JWT for `admin01`. Extract the `access_token` field.
2. Decode the JWT payload and confirm the `roles` claim contains `"Admin"` but not `"PaymentProcessor"`.
3. Send a GET request to `/api/payments/cards/raw` using the Admin JWT — this endpoint should only be accessible to the `PaymentProcessor` service account.
4. Record the HTTP status code. PAN and CVV data must never be returned regardless of the Admin role.
5. Open Log Analytics and run the KQL query from Evidence to Collect. Confirm a `SegregationOfDutiesDenied` event appears within 2 minutes with `principal = admin01`.

**Tools/Commands**

```bash
# Step 1 — Obtain Admin JWT
TOKEN=$(curl -s -X POST "https://foodapp.example.com/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "grant_type=password&username=admin01&password=AdminPass!23&scope=api.read" \
  | jq -r '.access_token')

# Step 2 — Confirm role claim
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '.roles'

# Step 3 — Attempt raw card data endpoint
curl -i -X GET "https://foodapp.example.com/api/payments/cards/raw" \
  -H "Authorization: Bearer $TOKEN"
```

**Expected Result**

- HTTP 403 Forbidden

**Pass Criteria**

- Status code is 403.
- No PAN, CVV, or card number data returned.
- Admin role does not grant access to payment processor scope.

**Expected Log Entry**

- Event: `SegregationOfDutiesDenied`
- Principal: `admin01`
- Resource: `/api/payments/cards/raw`
- Result: Deny

**Compliance**

- PCI-DSS v4.0 Req 3.3.1 — SAD (sensitive authentication data) access minimized and role-segregated.

---

### TC-003-06

**Type:** Edge
**Title:** Tampered JWT with modified role claim is rejected by signature validation

**Steps**

1. Obtain a valid Customer JWT for `customer01` using the token endpoint.
2. Split the JWT into its three parts (header.payload.signature). Decode the payload, change the `roles` field from `"Customer"` to `"Admin"`, re-encode it, and reassemble with the original signature — producing a structurally valid but cryptographically invalid token. This simulates an `alg:none` or signature-stripping attack.
3. Send a GET request to `/api/admin/users` using this tampered token in the `Authorization: Bearer` header.
4. Record the HTTP status code. The server must reject the token before any route logic executes.
5. Open Log Analytics and run the KQL query from Evidence to Collect. Confirm a `TokenValidationFailed` event appears with `principal = unknown` and the request was denied at the gateway layer, not the application layer.

**Tools/Commands**

```bash
# Step 1 — Obtain valid Customer JWT
VALID_TOKEN=$(curl -s -X POST "https://foodapp.example.com/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "grant_type=password&username=customer01&password=CustPass!23&scope=api.read" \
  | jq -r '.access_token')

# Step 2 — Tamper the payload (change role to Admin, keep original signature)
HEADER=$(echo $VALID_TOKEN | cut -d'.' -f1)
PAYLOAD=$(echo $VALID_TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null \
  | jq '.roles = ["Admin"]' | base64 -w0 | tr '+/' '-_' | tr -d '=')
SIG=$(echo $VALID_TOKEN | cut -d'.' -f3)
TAMPERED_TOKEN="${HEADER}.${PAYLOAD}.${SIG}"

# Step 3 — Attempt admin endpoint with tampered token
curl -i -X GET "https://foodapp.example.com/api/admin/users" \
  -H "Authorization: Bearer $TAMPERED_TOKEN"
```

**Expected Result**

- HTTP 401 Unauthorized

**Pass Criteria**

- Status code is 401.
- Signature validation fails at APIM before reaching the backend.
- Response body contains no admin data.

**Expected Log Entry**

- Event: `TokenValidationFailed`
- Principal: `unknown`
- Resource: `/api/admin/users`
- Result: Deny

**Compliance**

- PCI-DSS v4.0 Req 8.3.6 — strong cryptographic authentication mechanisms must be enforced and cannot be bypassed.

---

### TC-003-07

**Type:** Positive / Negative
**Title:** ABAC policy enforces profile ownership — own profile allowed, other profile denied

**Steps**

1. Send a POST to the token endpoint to obtain a Customer JWT for `customer01`. Extract the `access_token` field.
2. Send a GET request to `/api/customers/me` — the canonical self-reference endpoint. This should always resolve to the authenticated user's own profile.
3. Record the HTTP status code and confirm the response body contains `customer01`'s data only.
4. Now send a GET request to `/api/customers/customer02` using the same `customer01` JWT. This tests that the ABAC ownership attribute check prevents cross-customer profile access.
5. Open Log Analytics and run the KQL query from Evidence to Collect. Confirm `AuthorizationSuccess` for the `/me` call and `AuthorizationDenied` for the `/customer02` call, both with `principal = customer01`.

**Tools/Commands**

```bash
# Step 1 — Obtain Customer01 JWT
TOKEN=$(curl -s -X POST "https://foodapp.example.com/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "grant_type=password&username=customer01&password=CustPass!23&scope=api.read" \
  | jq -r '.access_token')

# Step 2 — Access own profile (should succeed)
curl -i -X GET "https://foodapp.example.com/api/customers/me" \
  -H "Authorization: Bearer $TOKEN"

# Step 3 — Attempt to access another customer's profile (should be denied)
curl -i -X GET "https://foodapp.example.com/api/customers/customer02" \
  -H "Authorization: Bearer $TOKEN"
```

**Expected Result**

- Own profile (`/me`): HTTP 200 OK
- Other customer's profile (`/customer02`): HTTP 403 Forbidden

**Pass Criteria**

- `/me` returns 200 with `customer01` data.
- `/customer02` returns 403 with no profile data.
- ABAC ownership attribute is enforced at the application layer.

**Expected Log Entry**

- Event: `AuthorizationSuccess` for `/me`, `AuthorizationDenied` for `/customer02`
- Principal: `customer01`
- Result: Mixed

**Compliance**

- GDPR Art. 25 — data protection by design and by default; access to personal data limited to the data subject's own records.

---

## Compliance Check

All authorization decisions are logged in Azure Monitor. Role-based access controls restrict function-level access by role. Ownership checks at the application layer prevent IDOR across customer data. Payment card data is segregated from Admin scope. JWT signature validation at the API Gateway prevents token forgery attacks.

## Evidence to Collect

- Screenshots of HTTP response headers and status codes for each test case.
- Decoded JWT payload showing role claims (use jwt.io or `base64 -d`).
- APIM trace logs from Azure Portal Developer Tools.
- Log Analytics query results exported as CSV.
- Audit events confirming allow/deny decisions per principal and resource.

**KQL Query — T003 Authorization Events:**

```kusto
AzureDiagnostics
| where requestUri_s contains "/api/"
| where Category in ("GatewayLogs", "ApplicationGatewayFirewallLog")
      or ResultType contains "Authorization"
| project TimeGenerated,
          identity_claim_name_s,
          requestUri_s,
          httpStatus_d,
          operationName_s,
          ResultType
| order by TimeGenerated desc
```

---
