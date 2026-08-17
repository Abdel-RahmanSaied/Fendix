# CORS Misconfiguration Check

**Engine:** Go (black-box)
**Category:** `cors`
**Default severity:** CRITICAL – LOW
**Active probing:** No (passive only)

## What It Detects

Cross-Origin Resource Sharing (CORS) misconfigurations that could allow unauthorized websites to read sensitive data from the API.

## Scenarios Detected

| Scenario | Severity |
|---|---|
| `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` | CRITICAL |
| Origin reflection (echoes back any Origin header) | HIGH |
| `Access-Control-Allow-Origin: *` (without credentials) | MEDIUM |
| Permissive `Access-Control-Allow-Methods` (includes PUT/DELETE/PATCH) | LOW |

## How It Works

1. Sends a request with `Origin: https://evil.example.com` header
2. Checks if the response reflects the malicious origin in `Access-Control-Allow-Origin`
3. Checks if credentials are allowed (`Access-Control-Allow-Credentials: true`)
4. Inspects allowed methods for overly permissive configurations

## Example Finding

```json
{
  "title": "CORS allows credentials with wildcard origin",
  "severity": "CRITICAL",
  "category": "cors",
  "endpoint": "GET /api/users",
  "evidence": "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
  "fix": "Never combine wildcard origin with credentials. Whitelist specific trusted origins."
}
```

## Confidence context (de-escalation, not suppression)

A CORS misconfiguration is reported at reduced **confidence score** (−15) in two
contexts. The finding itself is preserved — the origin genuinely is reflected —
and the reason is printed in `confidence_reasons`:

| Context | When | Why it lowers confidence |
|---|---|---|
| `4xx` | The misconfiguration was observed **only** on auth-gated responses (401/403/…), never on a 2xx | A policy seen only behind a gate is a weaker signal; if it also fired on a 2xx the finding stays at full confidence |
| `static-asset` | Path is a static file (`.js`, `.css`, images, fonts, `.map`, `favicon.ico`, `robots.txt`, `sitemap.xml`) | A permissive policy on a CDN-served asset is real but lower-impact than the same policy on an API route |

`4xx` takes precedence when both apply. Across a deduplicated group the context
survives only if every occurrence carried it.

## References

- [CWE-942: Overly Permissive Cross-domain Whitelist](https://cwe.mitre.org/data/definitions/942.html)
- [OWASP CORS Misconfiguration](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
