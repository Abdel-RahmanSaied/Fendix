# OpenAPI Spec Parser Check

**Engine:** Python (white-box)
**Category:** `auth`
**Default severity:** HIGH – LOW
**Active probing:** No (static analysis)

## What It Detects

Security misconfigurations in OpenAPI 2.0 (Swagger) and OpenAPI 3.x specifications, focusing on authentication and transport security issues.

## Checks Performed

| Check | Description | Severity |
|---|---|---|
| **No global security** | Spec has no top-level `security` or `securityDefinitions` | HIGH |
| **HTTP server scheme** | Spec defines `http://` servers (no TLS) | MEDIUM |
| **No-auth endpoint** | Individual endpoint has no security requirement and no global fallback | HIGH |
| **Basic auth scheme** | Spec uses HTTP Basic authentication (credentials sent in cleartext) | LOW |

## Supported Formats

- OpenAPI 2.0 (Swagger) — YAML and JSON
- OpenAPI 3.0.x — YAML and JSON
- OpenAPI 3.1.x — YAML and JSON

## How It Works

1. Parses the spec file (YAML or JSON)
2. Detects OpenAPI version (2.0 vs 3.x)
3. Checks for global security definitions
4. Iterates all paths/operations and checks for per-endpoint security
5. Inspects server URLs for HTTP vs HTTPS
6. Reports findings with the spec file path and operation as the endpoint

## Example Finding

```json
{
  "title": "Endpoint has no authentication requirement",
  "severity": "HIGH",
  "source": "whitebox",
  "category": "auth",
  "endpoint": "openapi.yaml:GET /api/admin/users",
  "evidence": "No security requirement defined for GET /api/admin/users and no global security fallback",
  "fix": "Add a security requirement to this endpoint or define a global security scheme.",
  "references": ["CWE-306"],
  "line": "openapi.yaml"
}
```

## References

- [CWE-306: Missing Authentication](https://cwe.mitre.org/data/definitions/306.html)
- [OpenAPI Specification](https://spec.openapis.org/oas/latest.html)
