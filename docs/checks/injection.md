# Injection Check

**Engine:** Go (black-box)
**Category:** `injection`
**Default severity:** CRITICAL – HIGH
**Active probing:** Yes (`--enable-active` required)

## What It Detects

Server-side injection vulnerabilities including SQL injection, command injection, and CRLF header injection. These checks send payloads to the target — they are **off by default** and require `--enable-active`.

## Checks Performed

### SQL Injection (time-based blind)

| Database | Payload | Detection |
|---|---|---|
| MySQL | `' AND SLEEP(5)--` | Response time > baseline + 4s |
| PostgreSQL | `' AND pg_sleep(5)--` | Response time > baseline + 4s |
| MSSQL | `'; WAITFOR DELAY '00:00:05'--` | Response time > baseline + 4s |

**How it works:**
1. Measures baseline response time (3-sample median)
2. Sends time-delay payload for each database type
3. If response takes significantly longer than baseline, reports potential SQLi
4. Sends a confirmation probe — HIGH confidence if both probes delayed, MEDIUM if only one

### Command Injection (echo canary)

**Payload:** `; echo fendix_canary_PROBE` (safe, non-destructive)

**How it works:**
1. Appends the echo canary payload to each parameter
2. Reads response body (up to 1MB)
3. If `fendix_canary_` appears in the response, the command was executed
4. Reports as CRITICAL severity with HIGH confidence

### CRLF Header Injection

**Payload:** `%0d%0aSet-Cookie:%20fendix=injected`

**How it works:**
1. Injects CRLF sequence into query parameter values
2. Checks response cookies for `fendix=injected`
3. If the injected cookie appears, CRLF injection is confirmed
4. Reports as HIGH severity

## Safety Measures

- All probes are gated behind `--enable-active` flag
- A legal disclaimer is printed when active probing is enabled
- Per-endpoint probe rate limit: maximum 20 probes per endpoint
- Full audit log records every probe sent (endpoint, payload, timestamp, result)
- No destructive payloads — echo canary for CMDi, time delay for SQLi

## Example Finding

```json
{
  "title": "Potential SQL Injection (MySQL SLEEP)",
  "severity": "HIGH",
  "category": "injection",
  "endpoint": "GET /api/search?q=test",
  "evidence": "Parameter 'q' responded in 5.2s (baseline: 0.3s) with SLEEP(5) payload",
  "fix": "Use parameterized queries. Never concatenate user input into SQL statements."
}
```

## References

- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-113: HTTP Response Splitting](https://cwe.mitre.org/data/definitions/113.html)
