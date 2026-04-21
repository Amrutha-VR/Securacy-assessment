import requests
import time
from collections import Counter
from datetime import datetime
from email.utils import parsedate_to_datetime

# ── Configuration ──────────────────────────────────────────
BASE_URL            = "https://foodapp.example.com"
LOGIN_PATH          = "/api/auth/login"
TOTAL_REQUESTS      = 101
REQUEST_DELAY_SECS  = 0.5   # 101 requests @ 0.5s = ~50s < 60s window
TIMEOUT             = 5
# ───────────────────────────────────────────────────────────

URL             = BASE_URL + LOGIN_PATH
results         = []
errors          = []
retry_after_raw = None
remaining_on_429 = None
start_time      = time.time()

print("=" * 60)
print("TC-004-02 — Rate Limit Enforcement Validation")
print(f"Target  : {URL}")
print(f"Requests: {TOTAL_REQUESTS} @ {REQUEST_DELAY_SECS}s intervals (~{TOTAL_REQUESTS * REQUEST_DELAY_SECS:.0f}s total)")
print(f"Started : {datetime.utcnow().isoformat()}Z")
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

        if code == 429 and retry_after_raw is None:
            retry_after_raw   = resp.headers.get("Retry-After")
            remaining_on_429  = resp.headers.get("X-RateLimit-Remaining", "not present")
            print(f"Request {i:03d}: {code}  <-- THROTTLED "
                  f"| Retry-After: {retry_after_raw} "
                  f"| X-RateLimit-Remaining: {remaining_on_429}")
        else:
            print(f"Request {i:03d}: {code}")

        time.sleep(REQUEST_DELAY_SECS)

    except Exception as ex:
        results.append("ERR")
        errors.append(str(ex))
        print(f"Request {i:03d}: ERROR — {ex}")

elapsed = time.time() - start_time

# ── Assertion helpers ──────────────────────────────────────

def parse_retry_after(value):
    """Accept both integer-seconds and HTTP-date Retry-After formats."""
    if value is None:
        return False
    if str(value).strip().isdigit():
        return int(value) > 0
    try:
        parsed = parsedate_to_datetime(str(value))
        return parsed > datetime.utcnow().replace(tzinfo=parsed.tzinfo)
    except Exception:
        return False

# ── Assertions ─────────────────────────────────────────────

first_100 = results[:100]

# A: No 429 in first 100 requests
assertion_a      = (429 not in first_100)
errors_in_first  = first_100.count("ERR")

# B: Request 101 is 429
assertion_b = (len(results) >= 101 and results[100] == 429)

# C: Retry-After header is valid
assertion_c = parse_retry_after(retry_after_raw)

# D: All 101 requests completed within the 60s window
assertion_d = (elapsed < 60)

all_passed = assertion_a and assertion_b and assertion_c and assertion_d

# ── Summary ────────────────────────────────────────────────

counts = Counter(results)

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print(f"Total requests      : {len(results)}")
print(f"Elapsed time        : {elapsed:.1f}s")
print(f"Network errors      : {len(errors)}")

if errors_in_first > 0:
    print(f"  WARNING: {errors_in_first} errors in first 100 — Assertion A may be unreliable")

print("\nResponse code breakdown:")
for code, count in sorted(counts.items(), key=lambda x: str(x[0])):
    print(f"  {code}: {count}")

print(f"\nRetry-After captured          : {retry_after_raw}")
print(f"X-RateLimit-Remaining on 429  : {remaining_on_429}")

print(f"\nAssertion A — No 429 in first 100 requests : {'PASS' if assertion_a else 'FAIL'}")
print(f"Assertion B — Request 101 returns 429      : {'PASS' if assertion_b else 'FAIL'}")
print(f"Assertion C — Retry-After is valid         : {'PASS' if assertion_c else 'FAIL'}")
print(f"Assertion D — All requests within 60s      : {'PASS' if assertion_d else 'FAIL'}")

print("\n" + "=" * 60)
print("FINAL RESULT:", "PASS" if all_passed else "FAIL")
print("=" * 60)
