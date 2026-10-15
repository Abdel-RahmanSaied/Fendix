"""Golden SARIF must validate against the official SARIF 2.1.0 schema.

With zero findings engine v3.6.0 wrote ``"rules": null``. The schema types
``rules`` as an array, GitHub's ``upload-sarif`` rejected the file, and every
clean scan failed at upload. The Go goldens in go/internal/reporters/testdata
(``*.golden.sarif``, including the zero-findings contract) are validated here
against the OASIS schema, vendored unmodified next to them.
"""

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft4Validator

TESTDATA = Path(__file__).resolve().parents[2] / "go" / "internal" / "reporters" / "testdata"
SCHEMA_PATH = TESTDATA / "sarif-schema-2.1.0.json"
# https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
SCHEMA_SHA256 = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"
GOLDENS = sorted(TESTDATA.glob("*.golden.sarif"))


@pytest.fixture(scope="module")
def validator():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft4Validator(schema)


def test_vendored_schema_is_the_official_one():
    assert hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest() == SCHEMA_SHA256


def test_zero_findings_golden_is_covered():
    assert TESTDATA / "sarif_zero_findings.golden.sarif" in GOLDENS


@pytest.mark.parametrize("golden", GOLDENS, ids=lambda path: path.name)
def test_golden_sarif_validates(validator, golden):
    errors = [f"{list(e.path)}: {e.message}" for e in validator.iter_errors(json.loads(golden.read_text(encoding="utf-8")))]
    assert errors == []


def test_null_rules_is_rejected(validator):
    """The check catches the v3.6.0 defect itself, not just a missing key."""
    doc = json.loads((TESTDATA / "sarif_zero_findings.golden.sarif").read_text(encoding="utf-8"))
    doc["runs"][0]["tool"]["driver"]["rules"] = None
    assert any(list(e.path) == ["runs", 0, "tool", "driver", "rules"] for e in validator.iter_errors(doc))
