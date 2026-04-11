# Rate Limiting Check

**Engine:** Go (black-box)
**Category:** `headers`
**Default severity:** MEDIUM
**Active probing:** No (passive only)

## What It Detects

Endpoints that lack rate limiting, making them vulnerable to brute-force attacks, credential stuffing, and denial-of-service.

## How It Works

1. Sends 20 rapid-fire identical requests to the endpoint (no delay between them)
2. Checks for rate-limiting indicators:
   - HTTP 429 (Too Many Requests) response
   - `X-RateLimit-*` headers
   - `Retry-After` header
   - `X-Rate-Limit-*` headers
3. If all 20 requests succeed without any throttling response, reports the finding

## Example Finding

```json
{
  "title": "No rate limiting detected",
  "severity": "MEDIUM",
  "category": "headers",
  "endpoint": "POST /api/login",
  "evidence": "20 identical requests succeeded without rate limiting (no 429, no X-RateLimit headers)",
  "fix": "Implement rate limiting. Return 429 with Retry-After header when threshold exceeded."
}
```

## References

- [CWE-770: Allocation of Resources Without Limits](https://cwe.mitre.org/data/definitions/770.html)
- [OWASP Rate Limiting](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks)
