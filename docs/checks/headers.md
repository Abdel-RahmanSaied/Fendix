# Security Headers Check

**Engine:** Go (black-box)
**Category:** `headers`
**Default severity:** MEDIUM – INFO
**Active probing:** No (passive only)

## What It Detects

Missing or misconfigured HTTP security headers that leave the application vulnerable to common web attacks like clickjacking, MIME sniffing, XSS, and man-in-the-middle attacks.

## Headers Checked

| Header | Expected | Missing Severity |
|---|---|---|
| `Strict-Transport-Security` | Present with `max-age` | MEDIUM |
| `Content-Security-Policy` | Present | MEDIUM |
| `X-Content-Type-Options` | `nosniff` | LOW |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | LOW |
| `X-XSS-Protection` | `0` (deprecated, should be disabled) | INFO |
| `Server` | Should not reveal version | INFO |
| `X-Powered-By` | Should not be present | INFO |

## How It Works

1. Sends a GET request to each discovered endpoint
2. Inspects the response headers
3. Reports missing or misconfigured headers with appropriate severity

## Example Finding

```json
{
  "title": "Missing Strict-Transport-Security header",
  "severity": "MEDIUM",
  "category": "headers",
  "endpoint": "GET /api/users",
  "evidence": "Response missing Strict-Transport-Security header",
  "fix": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"
}
```

## References

- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
