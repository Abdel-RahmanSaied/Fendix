"""Regression tests for the Python-layer accuracy audit (docs/PYTHON_LAYER_ACCURACY_AUDIT.md).

Each test encodes the *correct* behavior for one confirmed finding. The fixture
in each test is the minimal reproducer the audit used; the assertion is what the
engine should do once the bug is fixed. Test numbers (#N) map to the report.

Driven in-process via ASTAnalyzer / DepsAnalyzer / SpecParser to stay fast and
hermetic — same pattern as test_ast_analyzer.py.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from analyzers.ast_analyzer import ASTAnalyzer
from analyzers.deps import DepsAnalyzer
from analyzers.spec_parser import SpecParser


def _scan(code: str, *, language: str = "python") -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "t.py").write_text(code)
        out: list[dict] = []
        ASTAnalyzer(tmp, language).run(out.append)
        return out


def _scan_named(files: dict[str, str]) -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        for rel, content in files.items():
            p = Path(tmp, rel)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        out: list[dict] = []
        ASTAnalyzer(tmp).run(out.append)
        return out


def _ids(findings: list[dict]) -> set[str]:
    return {f["id"] for f in findings}


def _by_id(findings: list[dict], fid: str) -> list[dict]:
    return [f for f in findings if f["id"] == fid]


def _deps(files: dict[str, str]) -> list[dict]:
    """Scan deps with primary tools (pip-audit/npm/govulncheck) forced OFF so
    the curated-list path under test runs deterministically regardless of
    what's installed locally (mirrors test_deps.py's patch pattern)."""
    from unittest.mock import patch

    with tempfile.TemporaryDirectory() as tmp:
        for rel, content in files.items():
            Path(tmp, rel).write_text(content)
        out: list[dict] = []
        with patch("analyzers.deps.shutil.which", return_value=None):
            DepsAnalyzer(tmp).run(out.append)
        return out


def _spec(content: str, suffix: str = ".yaml") -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp, f"spec{suffix}")
        p.write_text(content)
        out: list[dict] = []
        SpecParser(str(p)).check_auth(out.append)
        return out


# ===================== P0 — propagation & scope =====================


class TestAugAssign:
    def test_augassign_cmdi(self) -> None:  # #1
        code = (
            "import os\nfrom flask import request\n"
            "def h():\n"
            "    cmd = 'ping '\n"
            "    cmd += request.args['host']\n"
            "    os.system(cmd)\n"
        )
        assert "SEC-PY_OS_SYSTEM" in _ids(_scan(code))

    def test_augassign_sqli(self) -> None:  # #1
        code = (
            "from flask import request\n"
            "def h(cursor):\n"
            "    q = 'SELECT * FROM t WHERE x='\n"
            "    q += request.args['x']\n"
            "    cursor.execute(q)\n"
        )
        assert "SEC-PY_SQL_INJECTION" in _ids(_scan(code))


class TestScopeShadowing:
    def test_inner_tainted_not_suppressed_by_outer_constant_cmdi(self) -> None:  # #17
        code = (
            "import os\nfrom flask import request\n"
            "name = 'default'\n"
            "def h():\n"
            "    name = request.args.get('cmd')\n"
            "    os.system(name)\n"
        )
        assert "SEC-PY_OS_SYSTEM" in _ids(_scan(code))

    def test_inner_tainted_not_suppressed_by_outer_constant_ssrf(self) -> None:  # #17
        code = (
            "import requests\nfrom flask import request\n"
            "url = 'https://safe'\n"
            "def h():\n"
            "    url = request.args.get('u')\n"
            "    requests.get(url)\n"
        )
        assert "SEC-PY_SSRF" in _ids(_scan(code))


class TestPropagationTargets:
    def test_tuple_unpacking_sqli(self) -> None:  # #25
        code = (
            "from flask import request\n"
            "def h(cursor):\n"
            "    q, _ = \"SELECT '\" + request.args['x'] + \"'\", 1\n"
            "    cursor.execute(q)\n"
        )
        assert "SEC-PY_SQL_INJECTION" in _ids(_scan(code))

    def test_attribute_target_sqli(self) -> None:  # #26
        code = (
            "from flask import request\n"
            "class V:\n"
            "    def h(self, cursor):\n"
            "        self.q = \"SELECT '\" + request.args['x'] + \"'\"\n"
            "        cursor.execute(self.q)\n"
        )
        assert "SEC-PY_SQL_INJECTION" in _ids(_scan(code))

    def test_dict_element_sqli(self) -> None:  # #27
        code = (
            "from flask import request\n"
            "def h(cursor):\n"
            "    d = {}\n"
            "    d['q'] = \"SELECT '\" + request.args['x'] + \"'\"\n"
            "    cursor.execute(d['q'])\n"
        )
        assert "SEC-PY_SQL_INJECTION" in _ids(_scan(code))

    def test_walrus_sqli(self) -> None:  # #28
        code = (
            "from flask import request\n"
            "def h(cursor):\n"
            "    cursor.execute(q := \"SELECT '\" + request.args['x'] + \"'\")\n"
        )
        assert "SEC-PY_SQL_INJECTION" in _ids(_scan(code))


# ================ P0 — import-shape / alias resolution ================


class TestAliasedSinks:
    def test_os_aliased_system(self) -> None:  # #9
        code = "import os as _o\n_o.system(cmd)\n"
        assert "SEC-PY_OS_SYSTEM" in _ids(_scan(code))

    def test_os_from_import_system(self) -> None:  # #9
        code = "from os import system\nsystem(cmd)\n"
        assert "SEC-PY_OS_SYSTEM" in _ids(_scan(code))

    def test_subprocess_aliased_shell_true(self) -> None:  # #10
        code = "import subprocess as sp\nsp.run(cmd, shell=True)\n"
        assert "SEC-PY_SUBPROCESS_SHELL" in _ids(_scan(code))

    def test_subprocess_from_import_shell_true(self) -> None:  # #10
        code = "from subprocess import run\nrun(cmd, shell=True)\n"
        assert "SEC-PY_SUBPROCESS_SHELL" in _ids(_scan(code))

    def test_requests_aliased_ssrf(self) -> None:  # #8
        code = "import requests as r\nr.get(url)\n"
        assert "SEC-PY_SSRF" in _ids(_scan(code))

    def test_requests_from_import_ssrf(self) -> None:  # #8
        code = "from requests import get\nget(url)\n"
        assert "SEC-PY_SSRF" in _ids(_scan(code))

    def test_pickle_from_import_loads(self) -> None:  # #11
        code = "from PKMOD import loads\nloads(data)\n".replace("PKMOD", "pickle")
        assert "SEC-PY_PICKLE_LOAD" in _ids(_scan(code))

    def test_yaml_from_import_load(self) -> None:  # #12
        code = "from yaml import load\nload(data)\n"
        assert "SEC-PY_YAML_UNSAFE_LOAD" in _ids(_scan(code))


# ========== P0 — route-index pre-pass must not abort the scan ==========


class TestRouteIndexRecursionGuard:
    def test_deep_expression_does_not_abort_injection_pass(self) -> None:  # #18
        deep = "x = " + "+".join(["a"] * 600) + "\n"
        clean = (
            "import os\nfrom flask import request\n"
            "def h():\n    os.system(request.args.get('c'))\n"
        )
        findings = _scan_named({"deep.py": deep, "clean.py": clean})
        assert "SEC-PY_OS_SYSTEM" in _ids(findings)


# ===================== P0 — SQL const-fold FPs =====================


class TestSqlConstFold:
    def test_constant_fstring_table_not_flagged(self) -> None:  # #15
        code = (
            "def h(cursor):\n"
            "    table = 'users'\n"
            "    cursor.execute(f'SELECT * FROM {table} WHERE active=1')\n"
        )
        assert "SEC-PY_SQL_INJECTION" not in _ids(_scan(code))

    def test_literal_concat_not_flagged(self) -> None:  # #15
        code = "def h(cursor):\n    cursor.execute('SELECT 1 ' + 'FROM t')\n"
        assert "SEC-PY_SQL_INJECTION" not in _ids(_scan(code))

    def test_zero_interp_fstring_not_flagged(self) -> None:  # #15
        code = "def h(cursor):\n    cursor.execute(f'SELECT 1 FROM t')\n"
        assert "SEC-PY_SQL_INJECTION" not in _ids(_scan(code))

    def test_real_fstring_sqli_still_flagged(self) -> None:
        code = (
            "from flask import request\n"
            "def h(cursor):\n"
            "    cursor.execute(f\"SELECT * FROM t WHERE x={request.args['x']}\")\n"
        )
        assert "SEC-PY_SQL_INJECTION" in _ids(_scan(code))


# ===================== P1 — source coverage =====================


class TestSourceCoverage:
    def test_cookies_source(self) -> None:  # #3
        code = "import os\nfrom flask import request\nos.system(request.cookies['c'])\n"
        f = _by_id(_scan(code), "SEC-PY_OS_SYSTEM")
        assert f and f[0].get("reachable") is True

    def test_headers_value_source(self) -> None:  # #4
        code = "import os\nfrom flask import request\nos.system(request.headers.get('X-Cmd'))\n"
        f = _by_id(_scan(code), "SEC-PY_OS_SYSTEM")
        assert f and f[0].get("reachable") is True

    def test_django_files_source(self) -> None:  # #6
        code = (
            "import os\n"
            "def h(request):\n"
            "    return os.path.join('/d', request.FILES['f'].name)\n"
        )
        assert "SEC-PY_PATH_TRAVERSAL" in _ids(_scan(code))

    def test_get_json_source(self) -> None:  # #5
        code = (
            "import os\nfrom flask import request\nos.system(request.get_json()['c'])\n"
        )
        f = _by_id(_scan(code), "SEC-PY_OS_SYSTEM")
        assert f and f[0].get("reachable") is True

    def test_ospath_join_with_recognized_source(self) -> None:  # #7
        code = (
            "import os\nfrom flask import request\n"
            "p = os.path.join('/data', request.cookies['f'])\nopen(p)\n"
        )
        assert "SEC-PY_PATH_TRAVERSAL" in _ids(_scan(code))


# ================= P1 — path-traversal false positives =================


class TestPathTraversalFP:
    def test_webbrowser_open_not_flagged(self) -> None:  # #14
        code = "import webbrowser\nwebbrowser.open(url)\n"
        assert "SEC-PY_PATH_TRAVERSAL" not in _ids(_scan(code))

    def test_driver_open_not_flagged(self) -> None:  # #14
        code = "def h(driver, target):\n    driver.open(target)\n"
        assert "SEC-PY_PATH_TRAVERSAL" not in _ids(_scan(code))

    def test_builtin_open_still_flagged(self) -> None:
        code = "from flask import request\nopen(request.args['f'])\n"
        assert "SEC-PY_PATH_TRAVERSAL" in _ids(_scan(code))

    def test_open_ospath_join_constants_not_flagged(self) -> None:  # #16
        code = "import os\nopen(os.path.join('/srv', 'x.txt'))\n"
        assert "SEC-PY_PATH_TRAVERSAL" not in _ids(_scan(code))

    def test_open_dunder_file_relative_not_flagged(self) -> None:  # #16
        code = "open(f'{__file__}/../data.txt')\n"
        assert "SEC-PY_PATH_TRAVERSAL" not in _ids(_scan(code))


# ============== P1 — XSS escaping-sanitizer recognition ==============


class TestXssSanitizer:
    def test_html_escape_before_markup_not_flagged(self) -> None:  # #24
        code = (
            "import html\nfrom markupsafe import Markup\nfrom flask import request\n"
            "def h():\n"
            "    name = html.escape(request.args.get('name'))\n"
            "    return Markup(name)\n"
        )
        assert "SEC-PY_XSS_HTML_SINK" not in _ids(_scan(code))

    def test_unescaped_markup_still_flagged(self) -> None:
        code = (
            "from markupsafe import Markup\nfrom flask import request\n"
            "def h():\n    return Markup(request.args.get('name'))\n"
        )
        assert "SEC-PY_XSS_HTML_SINK" in _ids(_scan(code))


# ===================== P1 — sink breadth =====================


class TestSinkBreadth:
    def test_httpx_ssrf(self) -> None:
        code = "import httpx\nfrom flask import request\nhttpx.get(request.args['u'])\n"
        assert "SEC-PY_SSRF" in _ids(_scan(code))

    def test_urlopen_from_import_ssrf(self) -> None:
        code = "from urllib.request import urlopen\nfrom flask import request\nurlopen(request.args['u'])\n"
        assert "SEC-PY_SSRF" in _ids(_scan(code))

    def test_executescript_sqli(self) -> None:
        code = (
            "from flask import request\n"
            "def h(cursor):\n"
            "    cursor.executescript('DROP TABLE t; ' + request.args['x'])\n"
        )
        assert "SEC-PY_SQL_INJECTION" in _ids(_scan(code))

    def test_marshal_loads(self) -> None:
        code = "import MARMOD\nMARMOD.loads(data)\n".replace("MARMOD", "marshal")
        assert "SEC-PY_PICKLE_LOAD" in _ids(_scan(code))

    def test_subprocess_getoutput(self) -> None:
        code = "import subprocess\nfrom flask import request\nsubprocess.getoutput(request.args['c'])\n"
        assert "SEC-PY_SUBPROCESS_SHELL" in _ids(_scan(code))


# ===================== P1/P2 — SCA / deps =====================


class TestDeps:
    def test_requirements_extras_pin(self) -> None:  # #20
        findings = _deps({"requirements.txt": "requests[security]==2.19.0\n"})
        ids = {f["id"] for f in findings}
        assert any("2018_18074" in i or "2023_32681" in i for i in ids)

    def test_prerelease_pin_vulnerable(self) -> None:  # #34
        findings = _deps({"requirements.txt": "django==3.2.0rc1\n"})
        assert any(f["severity"] != "INFO" for f in findings)

    def test_triple_equals_pin(self) -> None:  # #33
        findings = _deps({"requirements.txt": "pyyaml===5.0\n"})
        assert any(f["severity"] == "CRITICAL" for f in findings)

    def test_version_compare_no_truncation(self) -> None:
        from analyzers.deps import _is_vulnerable

        assert _is_vulnerable("1.9", "1.10") is True
        assert _is_vulnerable("1.10", "1.9") is False


# ===================== P2 — spec auth semantics =====================


class TestSpecAuth:
    def test_empty_object_global_security_flags_anon(self) -> None:  # #30
        spec = json.dumps(
            {
                "openapi": "3.0.0",
                "components": {
                    "securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}
                },
                "security": [{}],
                "paths": {"/x": {"get": {"responses": {}}}},
            }
        )
        ids = {f["id"] for f in _spec(spec, ".json")}
        assert "SEC-SPEC-NO-GLOBAL-AUTH" in ids or "SEC-SPEC-NO-AUTH" in ids

    def test_apikey_in_query_flagged(self) -> None:
        spec = json.dumps(
            {
                "openapi": "3.0.0",
                "components": {
                    "securitySchemes": {
                        "k": {"type": "apiKey", "in": "query", "name": "api_key"}
                    }
                },
                "security": [{"k": []}],
                "paths": {},
            }
        )
        ids = {f["id"] for f in _spec(spec, ".json")}
        assert "SEC-SPEC-APIKEY-QUERY" in ids


# ============= P2 — password heuristic false positives =============


class TestPasswordHeuristic:
    def test_secretary_not_flagged(self) -> None:  # #23
        code = "import hashlib\nhashlib.md5(secretary.encode())\n"
        assert "SEC-PY_WEAK_CRYPTO_PASSWORD" not in _ids(_scan(code))

    def test_real_password_still_flagged(self) -> None:
        code = "import hashlib\nhashlib.md5(password.encode())\n"
        assert "SEC-PY_WEAK_CRYPTO_PASSWORD" in _ids(_scan(code))


# ===================== P2 — contract robustness =====================


class TestContract:
    def test_checks_null_emits_done_line(self) -> None:
        import subprocess
        import sys

        engine = Path(__file__).parent.parent / "engine.py"
        proc = subprocess.run(
            [sys.executable, str(engine)],
            input='{"mode":"whitebox","checks":null,"code_path":""}',
            capture_output=True,
            text=True,
            cwd=str(engine.parent),
        )
        last = (proc.stdout or "").strip().splitlines()
        assert last, "engine produced empty stdout on checks:null"
        assert json.loads(last[-1]).get("done") is True

    def test_non_object_request_emits_done_line(self) -> None:
        import subprocess
        import sys

        engine = Path(__file__).parent.parent / "engine.py"
        proc = subprocess.run(
            [sys.executable, str(engine)],
            input="[1,2,3]",
            capture_output=True,
            text=True,
            cwd=str(engine.parent),
        )
        last = (proc.stdout or "").strip().splitlines()
        assert last, "engine produced empty stdout on non-object request"
        assert json.loads(last[-1]).get("done") is True


# ======================================================================
# P2 — remaining audit items (#31, #32, for/with binding)
# ======================================================================


class TestRemainingItems:
    def test_for_loop_target_binding_cmdi(self) -> None:  # for/with gap
        code = (
            "import os\nfrom flask import request\n"
            "def h():\n"
            "    for x in request.args.values():\n"
            "        os.system(x)\n"
        )
        f = [d for d in _scan(code) if d["id"] == "SEC-PY_OS_SYSTEM"]
        assert f and f[0].get("reachable") is True

    def test_npm_scoped_id_has_no_slash(self) -> None:  # #31
        import json as _json
        from unittest.mock import patch
        import tempfile as _tf

        audit_doc = _json.dumps(
            {
                "vulnerabilities": {
                    "@babel/traverse": {
                        "severity": "high",
                        "via": [{"url": "https://x"}],
                    }
                }
            }
        )

        class _P:
            returncode = 1
            stdout = audit_doc
            stderr = ""

        with _tf.TemporaryDirectory() as tmp:
            from pathlib import Path as _Path

            _Path(tmp, "package.json").write_text(
                '{"dependencies":{"@babel/traverse":"7.0.0"}}'
            )
            _Path(tmp, "package-lock.json").write_text("{}")
            out = []
            from analyzers.deps import DepsAnalyzer

            with (
                patch("analyzers.deps.shutil.which", return_value="/usr/bin/npm"),
                patch("analyzers.deps.subprocess.run", return_value=_P()),
            ):
                DepsAnalyzer(tmp).run(out.append)
        ids = [f["id"] for f in out]
        assert any("BABEL" in i for i in ids)
        assert all("/" not in i for i in ids)

    def test_global_security_empty_evidence_distinct(self) -> None:  # #32
        spec = json.dumps(
            {
                "openapi": "3.0.0",
                "components": {
                    "securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}
                },
                "security": [],
                "paths": {},
            }
        )
        findings = _spec(spec, ".json")
        ng = [f for f in findings if f["id"] == "SEC-SPEC-NO-GLOBAL-AUTH"]
        assert ng, "explicit security:[] should still flag NO-GLOBAL-AUTH"
        assert "anonymous access" in ng[0]["evidence"]
