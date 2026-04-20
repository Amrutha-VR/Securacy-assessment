## Threat Summary

No rate limiting is documented on the API Gateway, exposing all endpoints to credential stuffing attacks on the auth endpoint, card testing (carding) on the payment endpoint, menu scraping by competitors, denial-of-service through resource exhaustion, and backend database flooding. On a food delivery platform where availability during lunch and dinner peaks is business-critical, even a brief outage translates directly into lost orders and customer churn.

## Mitigation Summary

Configure Azure API Management with tiered rate limiting: authentication endpoints capped at 100 requests per minute per IP, payment endpoints at 10 requests per minute per authenticated user, and general API endpoints at 1000 requests per minute. Apply IP-based throttling for unauthenticated public endpoints. Implement circuit breakers to halt traffic forwarding during backend instability. Enable full APIM telemetry and Log Analytics alerting on 429 and 503 response spikes.

## Pre-conditions

- Azure API Management deployed and fronting all endpoints.
- Rate limit policies deployed per the APIM policy snippets shown in each test case.
- Auth endpoint: `POST /api/auth/login`
- Payment endpoint: `POST /api/payments/charge`
- Public endpoint: `GET /api/menu/public`
- Log Analytics workspace connected to APIM.
- `curl`, `jq`, and `tee` available in the test environment.
- Base URL: `https://foodapp.example.com`

---

## Test Cases

### TC-004-01

**Type:** Positive
**Title:** 99 authentication requests within 60 seconds do not trigger rate limiting

**Steps**

1. Confirm the APIM rate-limit-by-key policy is deployed on `/api/auth/login` by navigating to Azure Portal > API Management > APIs > Auth API > Inbound Policy and verifying the `calls="100" renewal-period="60"` fragment is present.
2. Wait for the current 60-second window to roll over (or use a fresh test IP) to ensure the counter starts at zero.
3. Execute the curl loop below sending exactly 99 POST requests with a valid JSON body. Pipe all output to `test_output_tc004_01.txt`.
4. Inspect the output file. Count all response codes — every line must be `200` or `401`. A single `429` in this batch is a FAIL.
5. Open Log Analytics and run the KQL query from Evidence to Collect. Confirm zero throttle events appear for this IP during the test window.

**Tools/Commands**

```bash
# Send 99 requests — all should pass
for i in $(seq 1 99); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST "https://foodapp.example.com/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"testuser","password":"testpass"}'
done | tee test_output_tc004_01.txt

# Verify no 429 appears
grep "429" test_output_tc004_01.txt && echo "FAIL — unexpected throttle" || echo "PASS — no throttle on 99 requests"
```

**Expected Result**

- All 99 responses return `200` or `401`.
- No `429` responses.

**Pass Criteria**

- Zero `429` status codes in `test_output_tc004_01.txt`.

**Policy Snippet**

```xml
<rate-limit-by-key calls="100" renewal-period="60"
  counter-key="@(context.Request.IpAddress)" />
```

**Compliance**

- PCI-DSS v4.0 Req 6.4.2 — automated attack protections must not block legitimate traffic.

---

### TC-004-02

**Type:** Negative
**Title:** 101st authentication request in the same 60-second window returns 429

**Steps**

1. Confirm the same APIM rate-limit-by-key policy from TC-004-01 is active. Do NOT reset the counter from TC-004-01 — continue in the same window, or re-run a fresh 101-request batch from a clean window.
2. Execute the curl loop below sending exactly 101 POST requests, piping all output with headers to `test_output_tc004_02.txt`.
3. Inspect the last response block in the output file. Confirm the status line reads `HTTP/1.1 429 Too Many Requests`.
4. Confirm the `Retry-After` header is present and contains a positive integer value indicating seconds until the window resets.
5. Open Log Analytics and run the KQL query from Evidence to Collect. Confirm a throttle event appears with `httpStatus_d = 429` and the correct `clientIP_s`.

**Tools/Commands**

```bash
# Send 101 requests — request 101 should be throttled
for i in $(seq 1 101); do
  echo "--- Request $i ---"
  curl -i -X POST "https://foodapp.example.com/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"testuser","password":"testpass"}'
  echo ""
done | tee test_output_tc004_02.txt

# Check last status code
tail -30 test_output_tc004_02.txt | grep "HTTP/"
# Check Retry-After header
grep -i "Retry-After" test_output_tc004_02.txt | tail -1
```

**Expected Result**

- Requests 1–100: `200` or `401`
- Request 101: `HTTP/1.1 429 Too Many Requests`
- `Retry-After` header present with a positive integer value.

**Pass Criteria**

- Status 429 on request 101.
- `Retry-After` header exists and value is a positive integer.
- Requests 1–100 contain no `429`.

**Policy Snippet**

```xml
<rate-limit-by-key calls="100" renewal-period="60"
  counter-key="@(context.Request.IpAddress)" />
```

**Compliance**

- PCI-DSS v4.0 Req 8.6.3 — authentication endpoints must be protected against brute force and credential stuffing.

---

### TC-004-03

**Type:** Negative
**Title:** 11th payment request in 60 seconds returns 429 with correct throttle headers

**Steps**

1. Obtain a valid user JWT by authenticating via `POST /api/auth/login` and extracting the `access_token`.
2. Confirm the payment endpoint policy `calls="10" renewal-period="60"` is deployed in APIM for `/api/payments/charge`.
3. Execute the curl loop below sending exactly 11 POST requests to the payment endpoint, each with a valid Authorization header and JSON body.
4. Inspect the 11th response. Confirm status is `429`, `X-RateLimit-Remaining` is `0`, and `Retry-After` is present.
5. Open Log Analytics and run the KQL query from Evidence to Collect. Confirm throttle event with `httpStatus_d = 429` and `requestUri_s` matching `/api/payments/charge`.

**Tools/Commands**

```bash
# Step 1 — Obtain JWT
TOKEN=$(curl -s -X POST "https://foodapp.example.com/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "grant_type=password&username=customer01&password=CustPass!23&scope=api.read" \
  | jq -r '.access_token')

# Step 2 — Send 11 payment requests
for i in $(seq 1 11); do
  echo "--- Payment Request $i ---"
  curl -i -X POST "https://foodapp.example.com/api/payments/charge" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"amount":10.00,"currency":"GBP","card_token":"tok_test_123"}'
  echo ""
done | tee test_output_tc004_03.txt

# Verify 11th response
grep -i "X-RateLimit-Remaining" test_output_tc004_03.txt | tail -1
grep -i "Retry-After" test_output_tc004_03.txt | tail -1
```

**Expected Result**

- Requests 1–10: `200` or `402`
- Request 11: `429 Too Many Requests`
- Headers on request 11: `X-RateLimit-Remaining: 0`, `Retry-After: <positive integer>`

**Pass Criteria**

- Status 429 on request 11.
- `X-RateLimit-Remaining: 0` present.
- `Retry-After` present and is a positive integer.

**Policy Snippet**

```xml
<rate-limit-by-key calls="10" renewal-period="60"
  counter-key="@(context.Request.Headers.GetValueOrDefault("Authorization",""))" />
```

**Compliance**

- PCI-DSS v4.0 Req 6.4.2 — payment endpoints must be protected against automated card testing (carding) attacks.

---

### TC-004-04

**Type:** Positive
**Title:** Rate limit counter resets correctly after the 60-second window expires

**Steps**

1. Immediately after triggering a 429 on the auth endpoint (e.g., after TC-004-02), note the `Retry-After` value from the throttled response.
2. Wait for the number of seconds specified in `Retry-After` plus 2 seconds as a buffer (or simply `sleep 62`).
3. Send a single POST request to `/api/auth/login` with a valid JSON body.
4. Record the HTTP status code. It must be `200` or `401` — confirming the counter has reset and the request is no longer throttled.
5. Optionally check the `X-RateLimit-Remaining` header to confirm it has returned to `100` (or near it), confirming a full window reset.

**Tools/Commands**

```bash
# Step 1 — Wait for window reset (use Retry-After value + buffer)
echo "Waiting 62 seconds for rate limit window to reset..."
sleep 62

# Step 2 — Send a single request after reset
curl -i -X POST "https://foodapp.example.com/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}'
```

**Expected Result**

- HTTP `200` or `401` (not `429`)
- `X-RateLimit-Remaining` header reset to maximum allowed value.

**Pass Criteria**

- No `429` returned on the first request after the window expires.
- Rate limit counter has reset — confirmed via `X-RateLimit-Remaining` header.

**Compliance**

- PCI-DSS v4.0 Req 10.2.1 — security controls must operate consistently and produce verifiable, auditable evidence across time windows.

---

### TC-004-05

**Type:** Negative
**Title:** Unauthenticated requests from a single IP exceed IP-based rate limit and are blocked

**Steps**

1. Confirm the APIM IP-based rate limit policy is deployed on `GET /api/menu/public` with `calls="200" renewal-period="60"`.
2. Start a fresh 60-second window to ensure the counter starts from zero for the test IP.
3. Execute the curl loop below sending 201 unauthenticated GET requests (no Authorization header) to the public menu endpoint.
4. Inspect the output — confirm requests 1–200 return `200 OK` and request 201 returns `429 Too Many Requests`.
5. Open Log Analytics and run the KQL query from Evidence to Collect. Confirm a throttle event for the test IP with `httpStatus_d = 429` and `requestUri_s = /api/menu/public`.

**Tools/Commands**

```bash
# Send 201 unauthenticated requests
for i in $(seq 1 201); do
  curl -s -o /dev/null -w "Request $i: %{http_code}\n" \
    "https://foodapp.example.com/api/menu/public"
done | tee test_output_tc004_05.txt

# Check last few responses
tail -5 test_output_tc004_05.txt
grep "429" test_output_tc004_05.txt | head -3
```

**Expected Result**

- Requests 1–200: `200 OK`
- Request 201+: `429 Too Many Requests`

**Pass Criteria**

- First `429` appears on or before request 201.
- No `429` before request 200.

**Policy Snippet**

```xml
<rate-limit-by-key calls="200" renewal-period="60"
  counter-key="@(context.Request.IpAddress)" />
```

**Compliance**

- PCI-DSS v4.0 Req 1.4.5 — controls must limit public-facing traffic exposure to prevent scraping and enumeration attacks.

---

### TC-004-06

**Type:** Edge
**Title:** Circuit breaker opens after repeated backend failures and returns 503

**Steps**

1. Confirm the APIM circuit breaker policy is configured with `errors="5" interval="60" trip-duration="30"` on the orders endpoint.
2. Simulate backend failures by temporarily pointing the APIM backend URL to an unavailable host, or by configuring the backend service to return HTTP 500 for all requests (use a mock server or Azure APIM mock response policy).
3. Send at least 6 consecutive requests to `GET /api/orders` — the first 5 may return `502` or `500` as APIM forwards to the failing backend. From the 6th request onward, APIM should open the circuit and return `503 Service Unavailable` without forwarding to the backend.
4. Confirm the response body or headers indicate the circuit is open (e.g., `Retry-After` header may be present indicating when the circuit resets after `trip-duration` seconds).
5. Open Log Analytics and run the KQL query from Evidence to Collect. Confirm `httpStatus_d = 503` entries appear, and that `backendResponseCode_d` is absent or null — proving APIM stopped forwarding requests to the backend.

**Tools/Commands**

```bash
# Send 6 requests to trigger circuit breaker
for i in $(seq 1 6); do
  echo "--- Request $i ---"
  curl -i "https://foodapp.example.com/api/orders"
  echo ""
  sleep 1
done | tee test_output_tc004_06.txt

# Check for 503 response
grep "HTTP/" test_output_tc004_06.txt
grep -i "Retry-After" test_output_tc004_06.txt
```

**Expected Result**

- Requests 1–5: `500` or `502` (backend failure forwarded)
- Request 6+: `503 Service Unavailable` (circuit open — no backend forwarding)

**Pass Criteria**

- `503` returned after the error threshold is reached.
- Log Analytics shows `backendResponseCode_d` is null for 503 entries, confirming APIM halted forwarding.

**Policy Snippet**

```xml
<backend>
  <forward-request timeout="30" fail-on-error-status-code="true" />
  <circuit-breaker errors-threshold="5" interval="60" trip-duration="30" />
</backend>
```

**Compliance**

- PCI-DSS v4.0 Req 12.10.5 — incident response and resilience controls must prevent cascading failures.

---

## Compliance Check

Rate limiting mitigates credential stuffing, carding, and scraping. IP-based controls protect unauthenticated public endpoints. Circuit breakers prevent backend cascading failures. All throttle and breaker events are logged with IP, endpoint, and timestamp for audit and incident response.

## Evidence to Collect

- Raw curl output files (`test_output_tc004_0X.txt`) showing all response codes.
- Response headers including `Retry-After`, `X-RateLimit-Remaining`, `X-RateLimit-Limit` for throttled requests.
- APIM Analytics dashboard screenshot showing request volume and 429/503 spike.
- Backend request count graph (before and after circuit breaker opens).
- Log Analytics throttle event export.

**KQL Query — T004 Rate Limit and Circuit Breaker Events:**

```kusto
AzureDiagnostics
| where httpStatus_d in (429, 503)
      or message has "rate limit"
      or message has "circuit"
| project TimeGenerated,
          requestUri_s,
          clientIP_s,
          httpStatus_d,
          message,
          backendResponseCode_d
| order by TimeGenerated desc
```

---
