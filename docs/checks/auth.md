# Authentication Check

**Engine:** Go (black-box)
**Category:** `auth` / `auth_bypass`
**Default severity:** CRITICAL
**Active probing:** No (passive only)

## What It Detects

Authentication and authorization failures on live API endpoints, including missing authentication, JWT validation bypasses, and IDOR vulnerabilities.

## Checks Performed

| Check | Description | Severity |
|---|---|---|
| **Unauthenticated access** | Endpoint returns 200 without any auth header | CRITICAL |
| **Malformed JWT accepted** | Server accepts `Authorization: Bearer invalid.jwt.token` | CRITICAL |
| **Expired JWT accepted** | Server accepts a JWT with `exp` in the past | CRITICAL |
| **alg:none bypass** | Server accepts a JWT with `"alg": "none"` (no signature) | CRITICAL |
| **IDOR** | Different user accounts can access each other's resources (requires `--auth-user2`) | HIGH |

## How It Works

### Unauthenticated access
1. Sends request to endpoint without any Authorization header
2. If response is 200 OK, the endpoint lacks authentication

### JWT bypass
1. Generates a malformed/expired/alg:none JWT using go-jwt
2. Sends the crafted token to the endpoint
3. If the server responds with 200, JWT validation is broken

### IDOR (two-account check)
1. Requires `--auth` and `--auth-user2` flags
2. Accesses a resource as user 1, then tries the same resource as user 2
3. If both succeed, the endpoint may have an IDOR vulnerability

## Example Finding

```json
{
  "title": "Expired JWT accepted",
  "severity": "CRITICAL",
  "category": "auth_bypass",
  "endpoint": "GET /api/users/me",
  "evidence": "Server returned 200 with expired JWT (exp: 2020-01-01T00:00:00Z)",
  "fix": "Validate JWT expiration. Reject tokens where exp < current time."
}
```

## References

- [CWE-306: Missing Authentication](https://cwe.mitre.org/data/definitions/306.html)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [OWASP A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
