# Sensitive Data Exposure Check

**Engine:** Go (black-box)
**Category:** `data_exposure`
**Default severity:** CRITICAL – INFO
**Active probing:** No (passive only)

## What It Detects

Sensitive data leaked in API responses, including passwords, secrets, tokens, stack traces, internal IP addresses, and sequential identifiers that suggest IDOR vulnerabilities.

## Patterns Detected

| Pattern | Example | Severity |
|---|---|---|
| Passwords in JSON responses | `"password": "secret123"` | CRITICAL |
| Secrets/API keys in responses | `"api_key": "sk-live-..."` | CRITICAL |
| Tokens with long values | `"token": "eyJhbG..."` | HIGH |
| Stack traces in error responses | `Traceback (most recent call last)` | MEDIUM |
| Sequential numeric IDs | `"id": 1, "id": 2, "id": 3` | MEDIUM |
| Internal IP addresses | `10.0.0.1`, `192.168.1.1`, `172.16.x.x` | LOW |
| Software version strings | `"version": "1.2.3"` | INFO |

## How It Works

1. Sends requests to each discovered endpoint
2. Scans response body with regex patterns for each data type
3. Truncates evidence to avoid including full secrets in reports
4. Reports findings with appropriate severity based on data sensitivity

## Example Finding

```json
{
  "title": "Password field in API response",
  "severity": "CRITICAL",
  "category": "data_exposure",
  "endpoint": "GET /api/users/1",
  "evidence": "Response body contains \"password\": \"s3cr...\" [truncated]",
  "fix": "Never include password fields in API responses. Use a serializer that excludes sensitive fields."
}
```

## References

- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- [OWASP A02: Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
