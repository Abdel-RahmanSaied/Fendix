# Dependency CVE Check

**Engine:** Python (white-box)
**Category:** `deps`
**Default severity:** CRITICAL – MEDIUM
**Active probing:** No (static analysis)

## What It Detects

Known security vulnerabilities (CVEs) in project dependencies by analyzing manifest files.

## Supported Manifest Files

| File | Ecosystem |
|---|---|
| `requirements.txt` | PyPI (Python) |
| `package.json` | npm (JavaScript/Node.js) |

## How It Works

### PyPI (Python)
1. Parses `requirements.txt` to extract package names and pinned versions
2. Primary: runs `pip-audit` for comprehensive CVE database lookup
3. Fallback: checks against a built-in known-vulnerability list (10 common PyPI vulns) when pip-audit is not available
4. Reports each vulnerable package with CVE ID and affected version range

### npm (JavaScript)
1. Parses `package.json` to extract `dependencies` and `devDependencies`
2. Primary: runs `npm audit --json` for CVE database lookup
3. Fallback: checks against a built-in known-vulnerability list (4 common npm vulns)
4. Reports findings with severity mapped from advisory data

## Built-in Known Vulnerabilities

The fallback list includes high-profile vulnerabilities for offline/air-gapped scanning:

**PyPI:** Django (multiple), Flask, requests, Jinja2, cryptography, Pillow, urllib3, PyYAML, numpy, setuptools

**npm:** lodash, minimist, axios, node-fetch

## Example Finding

```json
{
  "title": "Known vulnerability in Django 3.2.0",
  "severity": "HIGH",
  "source": "whitebox",
  "category": "deps",
  "endpoint": "requirements.txt:django==3.2.0",
  "evidence": "Django 3.2.0 is affected by CVE-2023-XXXXX (SQL injection in QuerySet)",
  "fix": "Upgrade to Django >= 3.2.18",
  "references": ["CVE-2023-XXXXX"],
  "line": "requirements.txt"
}
```

## References

- [CWE-1035: Using Components with Known Vulnerabilities](https://cwe.mitre.org/data/definitions/1035.html)
- [OWASP A06: Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
