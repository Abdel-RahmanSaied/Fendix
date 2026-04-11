"""OpenAPI spec parser — analyzes API specifications for security issues.

Supports OpenAPI 2.0 (Swagger) and 3.x specifications in YAML or JSON format.
Checks for missing authentication, insecure auth schemes, and undocumented
HTTP-only (non-TLS) server URLs.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import yaml


class SpecParser:
    """Parses and analyzes OpenAPI specifications for security issues.

    Supports:
    - OpenAPI 3.0.x / 3.1.x  (``openapi`` key)
    - Swagger 2.0             (``swagger`` key)
    Both YAML and JSON formats are accepted.
    """

    def __init__(self, spec_path: str) -> None:
        """Initialize with the path to an OpenAPI spec file."""
        self.spec_path = spec_path
        self._spec: dict | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self) -> dict:
        """Parse and return the raw spec dict. Cached after first call."""
        if self._spec is None:
            self._spec = self._parse_file()
        return self._spec

    def get_endpoints(self) -> list[dict]:
        """Return list of {method, path, parameters, security, operation_id} dicts."""
        spec = self.load()
        results: list[dict] = []
        paths = spec.get("paths") or {}
        if not isinstance(paths, dict):
            return results
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method in ("get", "post", "put", "patch", "delete", "options", "head"):
                op = path_item.get(method)
                if not isinstance(op, dict):
                    continue
                results.append({
                    "method": method.upper(),
                    "path": path,
                    "parameters": op.get("parameters", []),
                    "security": op.get("security"),  # None = inherits global
                    "operation_id": op.get("operationId", ""),
                    "tags": op.get("tags", []),
                })
        return results

    def check_auth(self, emit_fn: Callable[[dict], None]) -> None:
        """Emit findings for authentication/authorization issues in the spec."""
        try:
            spec = self.load()
        except (OSError, yaml.YAMLError, json.JSONDecodeError, ValueError) as exc:
            emit_fn({
                "id": "SEC-SPEC-PARSE",
                "title": "OpenAPI spec could not be parsed",
                "severity": "MEDIUM",
                "source": "whitebox",
                "category": "auth",
                "endpoint": self.spec_path,
                "evidence": str(exc),
                "fix": "Ensure the OpenAPI spec is valid YAML or JSON.",
                "references": [],
                "confidence": "HIGH",
                "line": self.spec_path,
            })
            return

        self._check_no_global_security(spec, emit_fn)
        self._check_http_scheme(spec, emit_fn)
        self._check_per_endpoint_auth(spec, emit_fn)
        self._check_basic_auth_over_http(spec, emit_fn)

    # ------------------------------------------------------------------
    # Private checks
    # ------------------------------------------------------------------

    def _check_no_global_security(
        self, spec: dict, emit_fn: Callable[[dict], None]
    ) -> None:
        """Flag specs that define security schemes but no global security requirement."""
        schemes = self._security_schemes(spec)
        global_security = spec.get("security")

        if schemes and not global_security:
            emit_fn({
                "id": "SEC-SPEC-NO-GLOBAL-AUTH",
                "title": "OpenAPI spec defines security schemes but no global security requirement",
                "severity": "MEDIUM",
                "source": "whitebox",
                "category": "auth",
                "endpoint": self.spec_path,
                "evidence": (
                    f"securityDefinitions/securitySchemes defined "
                    f"({', '.join(list(schemes)[:5])}) but no top-level 'security' applied."
                ),
                "fix": (
                    "Add a top-level 'security' field to enforce authentication by default, "
                    "then override with [] only on endpoints that are intentionally public."
                ),
                "references": ["CWE-306"],
                "confidence": "MEDIUM",
                "line": self.spec_path,
            })

    def _check_http_scheme(
        self, spec: dict, emit_fn: Callable[[dict], None]
    ) -> None:
        """Flag specs that allow HTTP (non-TLS) as a scheme or server URL."""
        version = self._version(spec)

        if version == "2":
            schemes = spec.get("schemes", [])
            if "http" in schemes:
                emit_fn({
                    "id": "SEC-SPEC-HTTP-SCHEME",
                    "title": "API allows unencrypted HTTP transport",
                    "severity": "HIGH",
                    "source": "whitebox",
                    "category": "auth",
                    "endpoint": self.spec_path,
                    "evidence": "Swagger 2.0 'schemes' includes 'http'.",
                    "fix": "Remove 'http' from 'schemes'. Only 'https' should be listed.",
                    "references": ["CWE-319"],
                    "confidence": "HIGH",
                    "line": self.spec_path,
                })
        else:
            servers = spec.get("servers", [])
            http_servers = [
                s.get("url", "") for s in servers
                if isinstance(s, dict) and s.get("url", "").startswith("http://")
            ]
            if http_servers:
                emit_fn({
                    "id": "SEC-SPEC-HTTP-SERVER",
                    "title": "API server URL uses unencrypted HTTP",
                    "severity": "HIGH",
                    "source": "whitebox",
                    "category": "auth",
                    "endpoint": self.spec_path,
                    "evidence": f"Server URL(s) use http://: {', '.join(http_servers[:3])}",
                    "fix": "Change server URLs to use https:// to enforce TLS.",
                    "references": ["CWE-319"],
                    "confidence": "HIGH",
                    "line": self.spec_path,
                })

    def _check_per_endpoint_auth(
        self, spec: dict, emit_fn: Callable[[dict], None]
    ) -> None:
        """Flag endpoints that explicitly override security with [] (anonymous access)."""
        global_security = spec.get("security")
        endpoints = self.get_endpoints()

        for ep in endpoints:
            ep_security = ep["security"]
            if ep_security is None:
                # Inherits global — only flag if global is also absent
                if not global_security:
                    emit_fn({
                        "id": "SEC-SPEC-NO-AUTH",
                        "title": "Endpoint has no authentication requirement",
                        "severity": "HIGH",
                        "source": "whitebox",
                        "category": "auth",
                        "endpoint": f"{ep['method']} {ep['path']}",
                        "evidence": (
                            f"{ep['method']} {ep['path']} has no security defined and "
                            f"there is no global security requirement."
                        ),
                        "fix": (
                            "Add a security requirement to this endpoint or define a global "
                            "security policy in the spec."
                        ),
                        "references": ["CWE-306"],
                        "confidence": "MEDIUM",
                        "line": self.spec_path,
                    })
            elif ep_security == []:
                # Explicitly open — flag as informational if global auth exists
                severity = "MEDIUM" if global_security else "HIGH"
                emit_fn({
                    "id": "SEC-SPEC-OPEN-ENDPOINT",
                    "title": "Endpoint explicitly allows unauthenticated access",
                    "severity": severity,
                    "source": "whitebox",
                    "category": "auth",
                    "endpoint": f"{ep['method']} {ep['path']}",
                    "evidence": (
                        f"{ep['method']} {ep['path']} has 'security: []' "
                        f"(explicitly unauthenticated)."
                    ),
                    "fix": (
                        "Verify this endpoint should truly be public. If so, document why. "
                        "If not, add the required security scheme."
                    ),
                    "references": ["CWE-306"],
                    "confidence": "HIGH",
                    "line": self.spec_path,
                })

    def _check_basic_auth_over_http(
        self, spec: dict, emit_fn: Callable[[dict], None]
    ) -> None:
        """Flag specs using HTTP Basic Auth (credentials in cleartext if not TLS)."""
        schemes = self._security_schemes(spec)
        basic_schemes = [
            name for name, defn in schemes.items()
            if isinstance(defn, dict) and defn.get("type") == "basic"
        ]
        if not basic_schemes:
            # OpenAPI 3.x uses "http" type with scheme: basic
            basic_schemes = [
                name for name, defn in schemes.items()
                if isinstance(defn, dict)
                and defn.get("type") == "http"
                and defn.get("scheme", "").lower() == "basic"
            ]

        if basic_schemes:
            emit_fn({
                "id": "SEC-SPEC-BASIC-AUTH",
                "title": "API uses HTTP Basic Authentication",
                "severity": "MEDIUM",
                "source": "whitebox",
                "category": "auth",
                "endpoint": self.spec_path,
                "evidence": (
                    f"Security scheme(s) use HTTP Basic auth: {', '.join(basic_schemes)}."
                ),
                "fix": (
                    "Replace Basic Authentication with a more secure scheme such as "
                    "OAuth 2.0, OpenID Connect, or API keys over TLS."
                ),
                "references": ["CWE-522"],
                "confidence": "HIGH",
                "line": self.spec_path,
            })

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _parse_file(self) -> dict:
        """Read and parse the spec file (YAML or JSON).

        Always returns a dict. Raises ValueError if the parsed content
        is not a dict (e.g., empty file, scalar value, list).
        """
        path = Path(self.spec_path)
        text = path.read_text(encoding="utf-8")
        if path.suffix in {".json"}:
            result = json.loads(text)
        else:
            result = yaml.safe_load(text)  # handles both YAML and JSON
        if not isinstance(result, dict):
            raise ValueError(
                f"Expected a YAML/JSON object (dict) but got {type(result).__name__}"
            )
        return result

    def _version(self, spec: dict) -> str:
        """Return '2' for Swagger 2.0, '3' for OpenAPI 3.x."""
        if "swagger" in spec:
            return "2"
        return "3"

    def _security_schemes(self, spec: dict) -> dict[str, Any]:
        """Return security scheme definitions, abstracting 2.0 vs 3.x structure."""
        if self._version(spec) == "2":
            defs = spec.get("securityDefinitions")
            return defs if isinstance(defs, dict) else {}
        components = spec.get("components")
        if not isinstance(components, dict):
            return {}
        schemes = components.get("securitySchemes")
        return schemes if isinstance(schemes, dict) else {}
