"""Tests for the ASTAnalyzer.

Verifies Python AST and JavaScript heuristic detection of dangerous patterns.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from analyzers.ast_analyzer import ASTAnalyzer

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "ast_target"


def _collect(path: str) -> list[dict]:
    findings: list[dict] = []
    ASTAnalyzer(path).run(findings.append)
    return findings


def _ids(findings: list[dict]) -> set[str]:
    return {f["id"] for f in findings}


# ---------------------------------------------------------------------------
# Python AST detection tests
# ---------------------------------------------------------------------------

class TestPythonAST:
    def test_os_system_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-PY_OS_SYSTEM" in _ids(findings)

    def test_eval_with_dynamic_arg_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-PY_EVAL" in _ids(findings)

    def test_subprocess_shell_true_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-PY_SUBPROCESS_SHELL" in _ids(findings)

    def test_sql_percent_formatting_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-PY_SQL_INJECTION" in _ids(findings)

    def test_sql_fstring_detected(self) -> None:
        """f-string SQL query should also be detected."""
        findings = _collect(str(FIXTURES_DIR))
        sql_findings = [f for f in findings if f["id"] == "SEC-PY_SQL_INJECTION"]
        assert len(sql_findings) >= 2  # % formatting and f-string

    def test_safe_eval_literal_not_flagged(self) -> None:
        """eval('1 + 1') with a literal should not be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "safe.py").write_text("result = eval('1 + 1')\n")
            findings = _collect(tmpdir)
            assert "SEC-PY_EVAL" not in _ids(findings)

    def test_safe_sql_not_flagged(self) -> None:
        """Parameterized query should not be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "safe.py").write_text(
                "cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_SQL_INJECTION" not in _ids(findings)

    def test_subprocess_no_shell_not_flagged(self) -> None:
        """subprocess.run(list, shell=False) should not be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "safe.py").write_text(
                "import subprocess\nsubprocess.run(['ls', '-la'], shell=False)\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_SUBPROCESS_SHELL" not in _ids(findings)

    def test_clean_file_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            import shutil
            shutil.copy(FIXTURES_DIR / "clean.py", Path(tmpdir) / "clean.py")
            findings = _collect(tmpdir)
            assert findings == []


# ---------------------------------------------------------------------------
# TASK-087: Static analyzer expansion — pickle, yaml, weak crypto, open
# redirect, SSRF, auth-header trust, multi-step SQLi via assignment
# ---------------------------------------------------------------------------

class TestPickleDeserialization:
    def test_pickle_loads_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-PY_PICKLE_LOAD" in _ids(findings)

    def test_pickle_finding_severity(self) -> None:
        findings = [f for f in _collect(str(FIXTURES_DIR)) if f["id"] == "SEC-PY_PICKLE_LOAD"]
        assert findings, "no pickle finding emitted"
        assert findings[0]["severity"] == "CRITICAL"
        assert "CWE-502" in findings[0]["references"]


class TestYamlUnsafeLoad:
    def test_yaml_load_default_loader_detected(self) -> None:
        """yaml.load() without Loader= flagged."""
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-PY_YAML_UNSAFE_LOAD" in _ids(findings)

    def test_yaml_unsafe_load_detected(self) -> None:
        """yaml.unsafe_load() flagged regardless of args."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "u.py").write_text("import yaml\nyaml.unsafe_load(s)\n")
            findings = _collect(tmpdir)
            assert "SEC-PY_YAML_UNSAFE_LOAD" in _ids(findings)

    def test_yaml_load_with_safeloader_not_flagged(self) -> None:
        """yaml.load(s, Loader=yaml.SafeLoader) is the safe form."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text(
                "import yaml\nyaml.load(s, Loader=yaml.SafeLoader)\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_YAML_UNSAFE_LOAD" not in _ids(findings)

    def test_yaml_safe_load_helper_not_flagged(self) -> None:
        """yaml.safe_load() is the recommended helper — not flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text("import yaml\nyaml.safe_load(s)\n")
            findings = _collect(tmpdir)
            assert "SEC-PY_YAML_UNSAFE_LOAD" not in _ids(findings)


class TestWeakCryptoForPasswords:
    def test_md5_password_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-PY_WEAK_CRYPTO_PASSWORD" in _ids(findings)

    def test_finding_emits_secrets_category(self) -> None:
        f = next(
            (f for f in _collect(str(FIXTURES_DIR)) if f["id"] == "SEC-PY_WEAK_CRYPTO_PASSWORD"),
            None,
        )
        assert f is not None
        assert f["category"] == "secrets"

    def test_md5_for_non_password_not_flagged(self) -> None:
        """hashlib.md5(data) where the var name doesn't suggest a password is fine."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text(
                "import hashlib\ndef checksum(payload):\n    return hashlib.md5(payload).hexdigest()\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_WEAK_CRYPTO_PASSWORD" not in _ids(findings)

    def test_hashlib_new_md5_detected(self) -> None:
        """hashlib.new('md5', password) is also flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "bad.py").write_text(
                "import hashlib\ndef store(password):\n    return hashlib.new('md5', password).hexdigest()\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_WEAK_CRYPTO_PASSWORD" in _ids(findings)

    def test_md5_with_pw_abbrev_detected(self) -> None:
        """hashlib.md5(pw.encode()) — `pw` is a common abbrev for password."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "bad.py").write_text(
                "import hashlib\ndef store(pw):\n    return hashlib.md5(pw.encode()).hexdigest()\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_WEAK_CRYPTO_PASSWORD" in _ids(findings)

    def test_md5_with_power_arg_not_flagged(self) -> None:
        """`power` contains 'pw' as substring but is not a password — no FP."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text(
                "import hashlib\ndef checksum(power):\n    return hashlib.md5(power).hexdigest()\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_WEAK_CRYPTO_PASSWORD" not in _ids(findings)


class TestOpenRedirect:
    def test_open_redirect_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-PY_OPEN_REDIRECT" in _ids(findings)

    def test_constant_redirect_not_flagged(self) -> None:
        """redirect('/dashboard') with a fixed string is safe."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text(
                "from flask import redirect\ndef home():\n    return redirect('/home')\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_OPEN_REDIRECT" not in _ids(findings)


class TestSSRF:
    def test_ssrf_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-PY_SSRF" in _ids(findings)

    def test_ssrf_constant_url_not_flagged(self) -> None:
        """requests.get('https://...') with a literal URL is not SSRF."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text(
                "import requests\ndef ping():\n    return requests.get('https://api.example.com/x')\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_SSRF" not in _ids(findings)

    def test_ssrf_resolved_constant_var_not_flagged(self) -> None:
        """requests.get(URL) where URL was assigned a literal earlier — not SSRF."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text(
                "import requests\ndef ping():\n    URL = 'https://api.example.com/x'\n    return requests.get(URL)\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_SSRF" not in _ids(findings)


class TestAuthHeaderTrust:
    def test_auth_header_trust_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-PY_AUTH_HEADER_TRUST" in _ids(findings)

    def test_finding_emits_auth_bypass_category(self) -> None:
        f = next(
            (f for f in _collect(str(FIXTURES_DIR)) if f["id"] == "SEC-PY_AUTH_HEADER_TRUST"),
            None,
        )
        assert f is not None
        assert f["category"] == "auth_bypass"

    def test_session_check_not_flagged(self) -> None:
        """if request.session.get(...) is a verified session, not a header — safe."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text(
                "from flask import request\ndef view():\n    if request.session.get('uid'):\n        return 'ok'\n    return 'no'\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_AUTH_HEADER_TRUST" not in _ids(findings)

    def test_subscript_form_detected(self) -> None:
        """if request.headers['X-Admin']: is also flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "bad.py").write_text(
                "from flask import request\ndef view():\n    if request.headers['X-Admin']:\n        return 'admin'\n    return 'no'\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_AUTH_HEADER_TRUST" in _ids(findings)

    def test_handler_arg_named_req_detected(self) -> None:
        """Flask-style handler arg named `req` (common abbreviation)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "bad.py").write_text(
                "def view(req):\n    if req.headers.get('X-Admin') == 'true':\n        return 'admin'\n    return 'no'\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_AUTH_HEADER_TRUST" in _ids(findings)


class TestTaintChain:
    """TASK-114: AST analyzer records a taint chain when it can prove
    user input flows from a request source to a dangerous sink. The
    chain is later used by the Go correlator to escalate matched
    findings to `Reachable=true`."""

    def test_inline_request_input_in_sink_yields_chain(self) -> None:
        """cursor.execute(request.args.get('q')) — chain records source→sink."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import request\n"
                "def handler(cursor):\n"
                "    cursor.execute(request.args.get('q'))\n"
            )
            findings = _collect(tmpdir)
            sql = [f for f in findings if f["id"] == "SEC-PY_SQL_INJECTION"]
            assert len(sql) == 1, f"expected 1 SQLi finding, got {len(sql)}"
            f = sql[0]
            assert f.get("reachable") is True
            assert isinstance(f.get("taint_chain"), list)
            assert len(f["taint_chain"]) >= 2, f["taint_chain"]
            # First link references request input; last link is the sink.
            assert "request.args" in f["taint_chain"][0]["expr"]
            assert "execute" in f["taint_chain"][-1]["expr"]

    def test_multi_step_assignment_yields_chain(self) -> None:
        """q = request.args.get('q'); sql = '...' + q; cursor.execute(sql) — full chain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import request\n"
                "def handler(cursor):\n"
                "    q = request.args.get('q')\n"
                "    sql = 'SELECT * FROM u WHERE id=' + q\n"
                "    cursor.execute(sql)\n"
            )
            findings = _collect(tmpdir)
            sql = [f for f in findings if f["id"] == "SEC-PY_SQL_INJECTION"]
            assert len(sql) == 1
            chain = sql[0].get("taint_chain") or []
            assert sql[0].get("reachable") is True
            # 3 links: source assignment, intermediate assignment, sink.
            assert len(chain) >= 3, f"expected ≥3 chain links, got {chain}"
            assert "request.args" in chain[0]["expr"]
            assert any("execute" in link["expr"] for link in chain)

    def test_constant_value_yields_no_chain(self) -> None:
        """sql = 'static + ' + str(uuid); cursor.execute(sql) — no source, no chain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "import uuid\n"
                "def handler(cursor):\n"
                "    sql = 'SELECT * FROM logs WHERE id=' + str(uuid.uuid4())\n"
                "    cursor.execute(sql)\n"
            )
            findings = _collect(tmpdir)
            sql = [f for f in findings if f["id"] == "SEC-PY_SQL_INJECTION"]
            # SQLi still flagged (BinOp + Call concat is still suspicious),
            # but no chain because no request source was traced.
            assert len(sql) == 1
            assert sql[0].get("reachable") is not True
            assert sql[0].get("taint_chain") is None or sql[0]["taint_chain"] == []

    def test_ssrf_chain_recorded(self) -> None:
        """requests.get(request.GET['url']) — SSRF with chain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "import requests\n"
                "def handler(request):\n"
                "    return requests.get(request.GET['url'])\n"
            )
            findings = _collect(tmpdir)
            ssrf = [f for f in findings if f["id"] == "SEC-PY_SSRF"]
            assert len(ssrf) == 1
            assert ssrf[0].get("reachable") is True
            assert any("request.GET" in link["expr"] for link in ssrf[0]["taint_chain"])

    def test_open_redirect_chain_recorded(self) -> None:
        """redirect(request.args.get('next')) — open redirect with chain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import request, redirect\n"
                "def handler():\n"
                "    return redirect(request.args.get('next'))\n"
            )
            findings = _collect(tmpdir)
            redir = [f for f in findings if f["id"] == "SEC-PY_OPEN_REDIRECT"]
            assert len(redir) == 1
            assert redir[0].get("reachable") is True
            assert any("request.args" in link["expr"] for link in redir[0]["taint_chain"])


class TestXSSHTMLSink:
    """TASK-120 — reachable XSS taint chains.

    The Python AST analyzer recognises three HTML-render sinks that
    bypass auto-escaping: `Markup` (Flask/MarkupSafe), `mark_safe`
    (Django), and `render_template_string` (Flask/Jinja2). When user
    input flows into the first argument, the chain is recorded and
    `reachable: true` is set — same shape as TASK-114's SQLi/SSRF/
    open-redirect chains.
    """

    def test_markup_with_request_arg_emits_chain(self) -> None:
        """Markup(request.args.get('x')) — reflective XSS with chain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import Markup, request\n"
                "def handler():\n"
                "    return Markup(request.args.get('msg'))\n"
            )
            findings = _collect(tmpdir)
            xss = [f for f in findings if f["id"] == "SEC-PY_XSS_HTML_SINK"]
            assert len(xss) == 1, f"got {[f['id'] for f in findings]}"
            assert xss[0].get("reachable") is True
            assert any("request.args" in link["expr"] for link in xss[0]["taint_chain"])

    def test_mark_safe_with_request_arg_emits_chain(self) -> None:
        """Django mark_safe(request.GET['x']) — XSS bypassing auto-escape."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from django.utils.safestring import mark_safe\n"
                "def handler(request):\n"
                "    return mark_safe(request.GET['msg'])\n"
            )
            findings = _collect(tmpdir)
            xss = [f for f in findings if f["id"] == "SEC-PY_XSS_HTML_SINK"]
            assert len(xss) == 1
            assert xss[0].get("reachable") is True
            assert any("request.GET" in link["expr"] for link in xss[0]["taint_chain"])

    def test_render_template_string_with_request_arg_emits_chain(self) -> None:
        """render_template_string(user_input) — SSTI + XSS path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import render_template_string, request\n"
                "def handler():\n"
                "    return render_template_string(request.args.get('tpl'))\n"
            )
            findings = _collect(tmpdir)
            xss = [f for f in findings if f["id"] == "SEC-PY_XSS_HTML_SINK"]
            assert len(xss) == 1
            assert xss[0].get("reachable") is True

    def test_multi_step_assignment_resolves(self) -> None:
        """msg = request.args.get('x'); html = Markup(msg) — chain across hop."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import Markup, request\n"
                "def handler():\n"
                "    msg = request.args.get('msg')\n"
                "    return Markup(msg)\n"
            )
            findings = _collect(tmpdir)
            xss = [f for f in findings if f["id"] == "SEC-PY_XSS_HTML_SINK"]
            assert len(xss) == 1
            assert xss[0].get("reachable") is True
            # Chain should have at least 2 links: source assignment + sink.
            assert len(xss[0]["taint_chain"]) >= 2

    def test_attribute_form_flask_markup_detected(self) -> None:
        """flask.Markup(request.args['x']) — attribute call form."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "import flask\n"
                "def handler():\n"
                "    return flask.Markup(flask.request.args['msg'])\n"
            )
            findings = _collect(tmpdir)
            xss = [f for f in findings if f["id"] == "SEC-PY_XSS_HTML_SINK"]
            # Attribute-form call resolves the sink name; the request
            # input is recognised via flask.request.args reference.
            assert len(xss) == 1, f"expected 1 XSS finding, got {[f['id'] for f in findings]}"

    def test_constant_arg_not_flagged(self) -> None:
        """Markup('<b>static</b>') — literal-only, no flow → no finding."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import Markup\n"
                "def banner():\n"
                "    return Markup('<b>welcome</b>')\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_XSS_HTML_SINK" not in _ids(findings)

    def test_variable_resolving_to_constant_not_flagged(self) -> None:
        """html = '<b>static</b>'; Markup(html) — still safe."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import Markup\n"
                "def banner():\n"
                "    html = '<b>welcome</b>'\n"
                "    return Markup(html)\n"
            )
            findings = _collect(tmpdir)
            # Constant-only chain isn't flagged: the variable resolves
            # to a Constant in scope, so _is_xss_html_sink returns False.
            assert "SEC-PY_XSS_HTML_SINK" not in _ids(findings)

    def test_no_user_input_chain_emits_finding_without_reachable(self) -> None:
        """Markup(other_func()) — non-literal arg → finding, but no chain.

        Matches the SQLi/SSRF/open-redirect posture: a non-literal arg
        to a known sink is suspicious regardless of whether we can trace
        the source. The finding fires; `reachable: true` is only set
        when the chain traces all the way back to a request source.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import Markup\n"
                "def render(x):\n"
                "    return Markup(some_helper(x))\n"
            )
            findings = _collect(tmpdir)
            xss = [f for f in findings if f["id"] == "SEC-PY_XSS_HTML_SINK"]
            assert len(xss) == 1
            # No request source traced — finding fires but isn't escalated.
            assert xss[0].get("reachable") is not True
            assert xss[0].get("taint_chain") is None or xss[0]["taint_chain"] == []

    def test_finding_shape_matches_other_reachable_findings(self) -> None:
        """XSS finding has the same fields as SQLi/SSRF/open-redirect."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import Markup, request\n"
                "def handler():\n"
                "    return Markup(request.args.get('x'))\n"
            )
            findings = _collect(tmpdir)
            xss = [f for f in findings if f["id"] == "SEC-PY_XSS_HTML_SINK"]
            assert len(xss) == 1
            f = xss[0]
            assert f["severity"] == "HIGH"
            assert f["confidence"] == "MEDIUM"
            assert f["source"] == "whitebox"
            assert f["category"] == "injection"
            assert "CWE-79" in f["references"]
            assert f["reachable"] is True
            assert isinstance(f["taint_chain"], list)
            for link in f["taint_chain"]:
                assert set(link.keys()) >= {"file", "line", "expr"}


class TestSQLConcatViaAssignment:
    """TASK-087 closes the multi-step SQLi gap.

    Previously, `cursor.execute(name)` was not flagged — the visitor only
    checked the literal first argument shape, not what the variable held.
    With intra-function scope tracking, an assignment of a BinOp/JoinedStr/Call
    earlier in the same function is now resolved at the execute() site.
    """

    def test_concat_via_var_detected(self) -> None:
        """sql = 'SELECT...' + var; cursor.execute(sql) — flagged."""
        findings = _collect(str(FIXTURES_DIR))
        sql = [f for f in findings if f["id"] == "SEC-PY_SQL_INJECTION"]
        # Fixture has 4 SQLi patterns: %, f-string, inline +, multi-step assignment.
        assert len(sql) >= 4, f"expected ≥4 SQLi findings, got {len(sql)}: {[f['endpoint'] for f in sql]}"

    def test_assigned_constant_not_flagged(self) -> None:
        """sql = 'SELECT * FROM users'; cursor.execute(sql) — fine."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text(
                "def f(cursor):\n    sql = 'SELECT * FROM users'\n    cursor.execute(sql)\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_SQL_INJECTION" not in _ids(findings)


# ---------------------------------------------------------------------------
# JavaScript heuristic detection tests
# ---------------------------------------------------------------------------

class TestJavaScriptHeuristic:
    def test_eval_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-JS_EVAL" in _ids(findings)

    def test_inner_html_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-JS_INNER_HTML" in _ids(findings)

    def test_document_write_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-JS_DOCUMENT_WRITE" in _ids(findings)

    def test_sql_template_literal_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-JS_SQL_TEMPLATE" in _ids(findings)

    def test_safe_textcontent_not_flagged(self) -> None:
        """textContent assignment should not trigger innerHTML finding."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "safe.js").write_text(
                "document.getElementById('x').textContent = userInput;\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-JS_INNER_HTML" not in _ids(findings)


# ---------------------------------------------------------------------------
# Finding structure tests
# ---------------------------------------------------------------------------

class TestFindingStructure:
    def test_required_fields_present(self) -> None:
        required = {"id", "title", "severity", "source", "category",
                    "endpoint", "evidence", "fix", "references", "confidence", "line"}
        findings = _collect(str(FIXTURES_DIR))
        for f in findings:
            missing = required - f.keys()
            assert not missing, f"Finding {f.get('id')} missing: {missing}"

    def test_source_is_whitebox(self) -> None:
        for f in _collect(str(FIXTURES_DIR)):
            assert f["source"] == "whitebox"

    def test_line_field_format(self) -> None:
        for f in _collect(str(FIXTURES_DIR)):
            assert ":" in f["line"]
            parts = f["line"].rsplit(":", 1)
            assert parts[1].isdigit()


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_nonexistent_path_no_findings(self) -> None:
        assert _collect("/nonexistent/path") == []

    def test_empty_directory_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            assert _collect(tmpdir) == []

    def test_syntax_error_file_skipped_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "broken.py").write_text("def (((broken syntax\n")
            findings = _collect(tmpdir)
            # Should not raise; may produce zero findings for the broken file
            assert isinstance(findings, list)

    def test_skips_node_modules(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nm = Path(tmpdir, "node_modules", "lib")
            nm.mkdir(parents=True)
            (nm / "index.js").write_text("eval(userInput);\n")
            assert _collect(tmpdir) == []
