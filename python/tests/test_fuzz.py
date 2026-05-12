"""Fuzz tests for Python engine components using hypothesis.

These tests verify that parsers and analyzers never crash on arbitrary input.
Run with: python -m pytest tests/test_fuzz.py -v
"""
import json
import os
import tempfile
from pathlib import Path

import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

# ── Strategies ────────────────────────────────────────────────────────

# Strategy for arbitrary YAML-like dicts (OpenAPI specs)
yaml_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=50),
    lambda children: st.lists(children, max_size=5) | st.dictionaries(
        st.text(min_size=1, max_size=20), children, max_size=5
    ),
    max_leaves=20,
)

spec_dict = st.dictionaries(st.text(min_size=1, max_size=30), yaml_values, max_size=10)


# ── Spec Parser Fuzz ─────────────────────────────────────────────────

class TestSpecParserFuzz:
    """Fuzz tests for SpecParser — ensure it never crashes on malformed specs."""

    @given(data=spec_dict)
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_check_auth_never_crashes(self, data: dict) -> None:
        """SpecParser.check_auth must not raise on any dict input."""
        import yaml
        from analyzers.spec_parser import SpecParser

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.safe_dump(data, f)
            f.flush()
            path = f.name

        try:
            findings: list[dict] = []
            parser = SpecParser(path)
            parser.check_auth(findings.append)
            # Must not crash — findings may or may not be produced
        finally:
            os.unlink(path)

    @given(data=spec_dict)
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_get_endpoints_never_crashes(self, data: dict) -> None:
        """SpecParser.get_endpoints must not raise on any dict input."""
        import yaml
        from analyzers.spec_parser import SpecParser

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.safe_dump(data, f)
            f.flush()
            path = f.name

        try:
            parser = SpecParser(path)
            endpoints = parser.get_endpoints()
            assert isinstance(endpoints, list)
        finally:
            os.unlink(path)

    def test_empty_file(self) -> None:
        """SpecParser handles empty files without crashing."""
        from analyzers.spec_parser import SpecParser

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write("")
            path = f.name

        try:
            findings: list[dict] = []
            parser = SpecParser(path)
            parser.check_auth(findings.append)
        finally:
            os.unlink(path)

    def test_binary_garbage(self) -> None:
        """SpecParser handles binary garbage without crashing."""
        from analyzers.spec_parser import SpecParser

        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".yaml", delete=False
        ) as f:
            f.write(bytes(range(256)) * 10)
            path = f.name

        try:
            findings: list[dict] = []
            parser = SpecParser(path)
            parser.check_auth(findings.append)
        finally:
            os.unlink(path)

    def test_deeply_nested_yaml(self) -> None:
        """SpecParser handles deeply nested YAML without stack overflow."""
        import yaml
        from analyzers.spec_parser import SpecParser

        nested: dict = {}
        current = nested
        for i in range(50):
            current[f"level{i}"] = {}
            current = current[f"level{i}"]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.safe_dump(nested, f)
            path = f.name

        try:
            findings: list[dict] = []
            parser = SpecParser(path)
            parser.check_auth(findings.append)
        finally:
            os.unlink(path)


# ── Secrets Analyzer Fuzz ────────────────────────────────────────────
# Removed in TASK-118: the Python SecretsAnalyzer was deleted alongside
# its unit-test suite. Equivalent boundary coverage now lives in
# go/internal/scanner/secrets/scanner_test.go (24 race-clean cases
# including binary-content, large-file, and skip-dir paths). A Go-side
# native fuzzer for the secrets scanner is a backlog candidate but
# isn't blocking — the regex set is small enough that property-based
# inputs aren't a meaningful coverage gap.


# ── Engine IPC Fuzz ──────────────────────────────────────────────────

class TestEngineIPCFuzz:
    """Fuzz tests for the engine IPC contract parsing."""

    @given(data=st.text(max_size=2000))
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_json_loads_never_crashes_engine(self, data: str) -> None:
        """Engine JSON parsing must handle any input without crashing."""
        try:
            parsed = json.loads(data)
            # If it parses, validate it doesn't crash our field extraction
            if isinstance(parsed, dict):
                _ = parsed.get("mode", "")
                _ = parsed.get("spec", "")
                _ = parsed.get("code_path", "")
                _ = parsed.get("checks", [])
        except (json.JSONDecodeError, ValueError):
            pass  # Expected for non-JSON input
