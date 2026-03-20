# Fendix — Security Testing Capabilities

## What Fendix Does

Fendix is a security scanner that finds vulnerabilities in APIs and source code before attackers do. It combines two approaches: testing live APIs with real HTTP requests (black-box) and analyzing source code without running it (white-box). When both approaches detect the same issue, the finding gets elevated confidence.

---

## Live API Security Testing

### Authentication & Access Control
- Detects API endpoints accessible without any authentication
- Tests for JWT token validation bypasses (malformed tokens, expired tokens, unsigned tokens)
- Detects broken access control where one user can access another user's data (IDOR)

### Browser Security (CORS)
- Detects misconfigured cross-origin policies that allow any website to make requests to the API
- Identifies configurations that could enable credential theft from browsers

### Security Headers
- Checks for missing HTTPS enforcement (HSTS)
- Checks for missing clickjacking protection (X-Frame-Options)
- Checks for missing Content Security Policy
- Detects server version information leakage

### Sensitive Data Exposure
- Detects passwords, API keys, and tokens returned in API responses
- Detects stack traces and internal error messages exposed to users
- Detects internal IP addresses leaked in responses

### Rate Limiting
- Detects endpoints with no rate limiting, which are vulnerable to brute-force attacks

---

## Source Code Security Analysis

### Hardcoded Secrets
- AWS access keys and secret keys
- Private cryptographic keys
- API tokens and passwords embedded in code
- Database connection strings with credentials
- JWT tokens committed to source control

### Injection Vulnerabilities
- SQL injection via string formatting (Python and JavaScript)
- Command injection via shell execution
- Code injection via eval/exec with user input
- Cross-site scripting (XSS) via innerHTML and document.write

### Vulnerable Dependencies
- Scans Python (requirements.txt) and JavaScript (package.json) dependencies
- Matches against known CVE database (14 known vulnerabilities tracked)
- Flags unpinned dependency versions

### API Specification Analysis
- Detects endpoints with no authentication requirement in OpenAPI specs
- Detects use of insecure HTTP instead of HTTPS
- Detects weak authentication schemes (HTTP Basic Auth)
- Identifies explicitly public endpoints that may need review

### Framework-Specific Checks
- Flask routes missing login protection
- Django views missing authentication mixins
- FastAPI routes missing auth dependencies
- JWT token decoding without signature verification

---

## Reporting & Integration

### Output Formats
- **JSON** — machine-readable for integration with other tools
- **HTML** — self-contained visual report with severity badges, summary statistics, and expandable finding details
- **SARIF** — GitHub-compatible format for pull request annotations (coming soon)

### Severity Classification
Every finding is rated on a five-level scale: **Critical**, **High**, **Medium**, **Low**, and **Info** — based on impact category, detection confidence, and whether multiple detection methods agree.

### CI/CD Pipeline Integration
- Can be configured to fail builds when Critical or High severity findings are detected
- Supports baseline diffing to show only new findings between scans

### Credential Safety
- All credentials used during testing are automatically redacted from reports
- Reports are safe to share across teams without risk of credential leakage

---

## Key Differentiators

1. **Hybrid approach** — Combines live API testing with static code analysis for higher confidence findings
2. **Zero configuration** — Point it at a URL and it discovers endpoints automatically
3. **Developer-first** — Integrates into CI/CD pipelines with pass/fail exit codes
4. **Safe by default** — Active/destructive tests are disabled unless explicitly enabled
5. **Single report** — Both API and code findings in one unified output
6. **No external dependencies** — HTML reports are fully self-contained, no internet required to view
