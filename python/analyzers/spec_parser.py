"""OpenAPI spec parser — analyzes API specifications for security issues.

Supports OpenAPI 2.0 (Swagger) and 3.x specifications in YAML or JSON format.
Checks for missing authentication, insecure auth schemes, and undocumented
HTTP-only (non-TLS) server URLs.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

import yaml

# Response size cap for remote (--spec URL) fetches (F-L9). Mirrors the Go
# crawler's `maxSpecBytes` (internal/scanner/crawler.go) so a hostile or
# accidentally-huge spec endpoint cannot stream gigabytes into memory and OOM
# the engine. GitHub's own OpenAPI spec is ~12 MB, so 50 MB leaves headroom.
_MAX_SPEC_BYTES = 50 * 1024 * 1024  # 50 MB


class _HTTPSOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses to follow a redirect off ``https://``.

    F-L9 defence in depth: a hostile --spec endpoint could 30x-redirect to
    ``http://`` (downgrade) or to a non-HTTP scheme. urllib's default handler
    already blocks ``file:``/``data:`` redirects, but we additionally pin the
    scheme to https so the transport guarantee from the original URL holds for
    every hop. Re-validating on redirect mirrors the Go crawler posture.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        if not newurl.lower().startswith("https://"):
            raise urllib.error.HTTPError(
                newurl, code,
                f"refusing redirect to non-https URL: {newurl}",
                headers, fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class SpecParser:
    """Parses and analyzes OpenAPI specifications for security issues.

    Supports:
    - OpenAPI 3.0.x / 3.1.x  (``openapi`` key)
    - Swagger 2.0             (``swagger`` key)
    Both YAML and JSON formats are accepted.
    """

    def __init__(self, spec_path: str) -> None:
        """Initialize with the path to an OpenAPI spec file or URL."""
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
        except (OSError, yaml.YAMLError, json.JSONDecodeError, ValueError, RecursionError) as exc:
            # F-L8: RecursionError is included so a deeply-nested YAML/JSON spec
            # (a parser-recursion "bomb") is reported as an unparseable spec
            # rather than propagating out and aborting the whole auth check.
            # str(RecursionError) is often empty; fall back to the class name so
            # the evidence field is never blank.
            evidence = str(exc) or type(exc).__name__
            emit_fn({
                "id": "SEC-SPEC-PARSE",
                "title": "OpenAPI spec could not be parsed",
                "severity": "MEDIUM",
                "source": "whitebox",
                "category": "auth",
                "endpoint": self.spec_path,
                "evidence": evidence,
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

        Accepts a local path or an HTTP/HTTPS URL (mirroring the Go
        engine's ``loadSpec`` which gained URL support in TASK-082).

        Always returns a dict. Raises ValueError if the parsed content
        is not a dict (e.g., empty file, scalar value, list).
        """
        src = self.spec_path
        lower = src.lower()
        if lower.startswith("http://"):
            # F-L9: reject plaintext HTTP for the spec SOURCE as defence in
            # depth (SSRF-allowlist parity with the Go crawler is accepted;
            # the must-fix is the size cap below). A spec fetched over http://
            # can be tampered with in transit and is the easiest pivot for an
            # attacker-controlled --spec endpoint. https only.
            raise ValueError(
                "refusing to fetch spec over plaintext HTTP; use https://"
            )
        if lower.startswith("https://"):
            text, is_json = self._fetch_url(src, lower)
        else:
            path = Path(src)
            # F-L10/F-L9: cap the LOCAL spec read too. A local --spec path under
            # an untrusted repo could be an inflated multi-GB file; refuse to
            # slurp anything over the same size cap used for remote fetches.
            # The size guard runs before read_text() so we never buffer the
            # whole file. ValueError is turned into SEC-SPEC-PARSE by check_auth.
            if path.stat().st_size > _MAX_SPEC_BYTES:
                raise ValueError(
                    f"spec too large (> {_MAX_SPEC_BYTES} bytes): {src}"
                )
            text = path.read_text(encoding="utf-8")
            is_json = path.suffix == ".json"
        if is_json:
            result = json.loads(text)
        else:
            result = yaml.safe_load(text)  # handles both YAML and JSON
        if not isinstance(result, dict):
            raise ValueError(
                f"Expected a YAML/JSON object (dict) but got {type(result).__name__}"
            )
        return result

    def _fetch_url(self, src: str, lower: str) -> tuple[str, bool]:
        """Fetch a spec from an ``https://`` URL with a hard size cap.

        F-L9: streams at most ``_MAX_SPEC_BYTES`` bytes from the response so a
        hostile or accidentally-huge --spec endpoint can't OOM the engine —
        the LimitReader equivalent of the Go crawler's ``maxSpecBytes`` cap.
        We read one extra byte and raise if the body exceeds the cap rather
        than silently truncating a valid-but-large spec into invalid YAML.

        Redirects are re-validated to stay on ``https://`` via
        ``_HTTPSOnlyRedirectHandler`` (defence in depth: a redirect to
        http:// or to a non-HTTP scheme is rejected).
        """
        opener = urllib.request.build_opener(_HTTPSOnlyRedirectHandler())
        req = urllib.request.Request(
            src,
            headers={"Accept": "application/json, application/yaml, */*"},
        )
        with opener.open(req, timeout=30) as resp:  # noqa: S310
            # Read cap+1 bytes; anything beyond the cap means the body is too
            # large to trust. read(n) on an http response is bounded, so this
            # never buffers more than _MAX_SPEC_BYTES+1 bytes.
            raw = resp.read(_MAX_SPEC_BYTES + 1)
            content_type = resp.headers.get("Content-Type") or ""
        if len(raw) > _MAX_SPEC_BYTES:
            raise ValueError(
                f"spec too large (> {_MAX_SPEC_BYTES} bytes) from {src}"
            )
        text = raw.decode("utf-8")
        is_json = lower.endswith(".json") or "json" in content_type
        return text, is_json

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
