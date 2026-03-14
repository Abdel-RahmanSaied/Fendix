"""OpenAPI spec parser — analyzes API specifications for security issues.

Supports OpenAPI 2.0 (Swagger) and 3.x specifications in YAML or JSON format.
Checks for missing authentication, insecure auth schemes, and undocumented endpoints.
"""
from __future__ import annotations

from typing import Callable


class SpecParser:
    """Parses and analyzes OpenAPI specifications for security issues."""

    def __init__(self, spec_path: str) -> None:
        self.spec_path = spec_path

    def get_endpoints(self) -> list[dict]:
        """Return list of {method, path, parameters, security, operationId}."""
        return []

    def check_auth(self, emit_fn: Callable[[dict], None]) -> None:
        """Check for auth-related issues in the spec. Implementation in TASK-030."""
        pass
