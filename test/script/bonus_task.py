
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
