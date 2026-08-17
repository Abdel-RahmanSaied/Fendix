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

## Confidence context (de-escalation, not suppression)

Two response contexts lower a header finding's **confidence score** by 15 points
without removing the finding — the header genuinely is absent, so the evidence is
preserved (Product Constitution Rule 3) and the reason appears in the finding's
`confidence_reasons`:

| Context | When | Why it lowers confidence |
|---|---|---|
| `4xx` | Response was 401 / 403 / 405 / 406 / 429 | This is the auth-gated response an unauthenticated probe sees, not the app's real response surface |
| `static-asset` | Path is a static file (`.js`, `.css`, images, fonts, `.map`, `favicon.ico`, `robots.txt`, `sitemap.xml`) | Served by a CDN or static-file middleware, so an app-layer header expectation is a weaker signal than on an API route |

`4xx` takes precedence when both apply. Separately, responses with **404 / 410 /
5xx** are skipped outright — those headers are framework-controlled noise, not a
finding at reduced confidence.

When a finding is deduplicated across several endpoints, the context survives only
if **every** occurrence in the group carried it, so one static asset cannot
de-escalate a group that also covers real API routes.

## References

- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
