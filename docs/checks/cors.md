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

## References

- [CWE-942: Overly Permissive Cross-domain Whitelist](https://cwe.mitre.org/data/definitions/942.html)
- [OWASP CORS Misconfiguration](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
