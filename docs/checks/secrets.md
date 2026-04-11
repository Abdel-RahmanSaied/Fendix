# Secrets Detection Check

**Engine:** Python (white-box)
**Category:** `secrets`
**Default severity:** CRITICAL – MEDIUM
**Active probing:** No (static analysis)

## What It Detects

Hardcoded secrets, credentials, and API keys embedded directly in source code.

## Pattern Types

| Pattern | Example Match | Severity |
|---|---|---|
| **AWS Access Key ID** | `AKIAIOSFODNN7EXAMPLE` | CRITICAL |
| **AWS Secret Key** | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | CRITICAL |
| **Private Key (PEM)** | `-----BEGIN RSA PRIVATE KEY-----` | CRITICAL |
| **Generic API Key** | `api_key = "sk-live-abc123def456"` | HIGH |
| **Hardcoded Password** | `password = "mysecretpassword"` | HIGH |
| **JWT Secret** | `jwt_secret = "my-signing-key"` | HIGH |
| **Database Connection String** | `postgres://user:pass@host/db` | HIGH |

## How It Works

1. Recursively walks all files in `--code` directory
2. Skips binary files, `.git/`, `node_modules/`, `vendor/` directories
3. Applies regex patterns line-by-line against file contents
4. Truncates and masks matched secrets in evidence (never exposes full secret)
5. Reports file path and line number for each finding

## Example Finding

```json
{
  "title": "AWS Access Key ID detected",
  "severity": "CRITICAL",
  "source": "whitebox",
  "category": "secrets",
  "endpoint": "src/config.py:14",
  "evidence": "AKIA...MPLE [masked]",
  "fix": "Remove hardcoded key. Use environment variables or a secrets manager. Rotate the exposed key immediately.",
  "references": ["CWE-798"],
  "line": "src/config.py:14"
}
```

## References

- [CWE-798: Hardcoded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-321: Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
