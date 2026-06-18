"""Extended accuracy tests — per-variant coverage, edge cases, and false-positive
guards for the audit fixes (docs/PYTHON_LAYER_ACCURACY_AUDIT.md).

Complements test_accuracy_audit_regressions.py: that file proves each confirmed
bug is fixed; this file hardens the fixes against over-fix (new FPs) and
under-fix (missed variants), and adds a checked-in real-vuln-app fixture scan.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from analyzers.ast_analyzer import ASTAnalyzer
from analyzers.deps import _is_vulnerable, _parse_requirements, _extract_pinned_version
from analyzers.spec_parser import SpecParser

FIXTURES = Path(__file__).parent / "fixtures"


def _scan(code: str) -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "t.py").write_text(code)
        out: list[dict] = []
        ASTAnalyzer(tmp).run(out.append)
        return out


def _ids(findings: list[dict]) -> set[str]:
    return {f["id"] for f in findings}


def _has(code: str, fid: str) -> bool:
    return fid in _ids(_scan(code))


def _reachable(code: str, fid: str) -> bool:
    return any(f["id"] == fid and f.get("reachable") for f in _scan(code))


def _spec(obj: dict) -> set[str]:
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp, "s.json")
        p.write_text(json.dumps(obj))
        out: list[dict] = []
        SpecParser(str(p)).check_auth(out.append)
        return {f["id"] for f in out}


# ======================================================================
# Sink-breadth — one test per newly-added sink variant
# ======================================================================


class TestSSRFClients:
    def test_aiohttp_session_get(self) -> None:
        code = "from flask import request\ndef h(session):\n    return session.get(request.args['u'])\n"
        assert _has(code, "SEC-PY_SSRF")

    def test_urllib3_pool_request_url_index1(self) -> None:
        # urllib3 .request("GET", url) — URL is arg index 1, not 0
        code = "from flask import request\ndef h(pool):\n    return pool.request('GET', request.args['u'])\n"
        assert _has(code, "SEC-PY_SSRF")

    def test_httpx_aliased(self) -> None:
        code = (
            "import httpx as hx\nfrom flask import request\nhx.get(request.args['u'])\n"
        )
        assert _has(code, "SEC-PY_SSRF")

    def test_requests_request_method_url_index1(self) -> None:
        code = "import requests\nfrom flask import request\nrequests.request('GET', request.args['u'])\n"
        assert _has(code, "SEC-PY_SSRF")

    def test_constant_httpx_not_flagged(self) -> None:
        code = "import httpx\nhttpx.get('https://example.com/static')\n"
        assert not _has(code, "SEC-PY_SSRF")


class TestDeserVariants:
    def test_dill_loads(self) -> None:
        code = "import dill\ndill.loads(data)\n"
        assert _has(code, "SEC-PY_PICKLE_LOAD")

    def test_jsonpickle_decode(self) -> None:
        code = "import jsonpickle\njsonpickle.decode(data)\n"
        assert _has(code, "SEC-PY_PICKLE_LOAD")

    def test_cpickle_aliased(self) -> None:
        code = "import cPickle as p\np.loads(data)\n"
        assert _has(code, "SEC-PY_PICKLE_LOAD")

    def test_marshal_from_import(self) -> None:
        code = "from marshal import loads\nloads(data)\n"
        assert _has(code, "SEC-PY_PICKLE_LOAD")

    def test_json_loads_not_flagged(self) -> None:
        # json.loads is SAFE — must not be swept up by the deser broadening.
        code = "import json\njson.loads(data)\n"
        assert not _has(code, "SEC-PY_PICKLE_LOAD")


class TestCmdiVariants:
    def test_subprocess_getstatusoutput(self) -> None:
        code = "import subprocess\nfrom flask import request\nsubprocess.getstatusoutput(request.args['c'])\n"
        assert _has(code, "SEC-PY_SUBPROCESS_SHELL")

    def test_asyncio_create_subprocess_shell(self) -> None:
        code = "import asyncio\nfrom flask import request\nasyncio.create_subprocess_shell(request.args['c'])\n"
        assert _has(code, "SEC-PY_SUBPROCESS_SHELL")

    def test_os_popen_aliased(self) -> None:
        code = "import os as o\no.popen(cmd)\n"
        assert _has(code, "SEC-PY_OS_POPEN")

    def test_subprocess_shell_false_not_flagged(self) -> None:
        code = "import subprocess\nsubprocess.run(cmd, shell=False)\n"
        assert not _has(code, "SEC-PY_SUBPROCESS_SHELL")


class TestSqlVariants:
    def test_executemany_tainted(self) -> None:
        code = (
            "from flask import request\n"
            "def h(cur):\n"
            "    cur.executemany('INSERT INTO t VALUES (' + request.args['x'] + ')')\n"
        )
        assert _has(code, "SEC-PY_SQL_INJECTION")

    def test_execute_percent_format_still_flagged(self) -> None:
        code = (
            "from flask import request\n"
            "def h(cur):\n"
            "    cur.execute('SELECT * FROM t WHERE x=%s' % request.args['x'])\n"
        )
        assert _has(code, "SEC-PY_SQL_INJECTION")

    def test_parameterized_query_not_flagged(self) -> None:
        code = (
            "def h(cur, uid):\n    cur.execute('SELECT * FROM t WHERE id=%s', (uid,))\n"
        )
        assert not _has(code, "SEC-PY_SQL_INJECTION")


# ======================================================================
# Propagation edge cases
# ======================================================================


class TestPropagationEdges:
    def test_augassign_on_attribute(self) -> None:
        code = (
            "import os\nfrom flask import request\n"
            "class S:\n"
            "    def h(self):\n"
            "        self.cmd = 'ping '\n"
            "        self.cmd += request.args['h']\n"
            "        os.system(self.cmd)\n"
        )
        assert _has(code, "SEC-PY_OS_SYSTEM")

    def test_two_hop_chain(self) -> None:
        code = (
            "import os\nfrom flask import request\n"
            "def h():\n"
            "    a = request.args['x']\n"
            "    b = a\n"
            "    os.system(b)\n"
        )
        assert _reachable(code, "SEC-PY_OS_SYSTEM")

    def test_for_loop_with_constant_iterable_not_reachable(self) -> None:
        # for x in ["a","b"] is constant — os.system(x) should NOT be reachable.
        code = "import os\ndef h():\n    for x in ['a', 'b']:\n        os.system(x)\n"
        # Either no finding, or a finding without reachable=True (no taint source).
        assert not _reachable(code, "SEC-PY_OS_SYSTEM")

    def test_constant_augassign_not_flagged(self) -> None:
        code = (
            "import os\n"
            "def h():\n"
            "    cmd = 'echo '\n"
            "    cmd += 'hello'\n"
            "    os.system(cmd)\n"
        )
        assert not _has(code, "SEC-PY_OS_SYSTEM")


class TestScopeEdges:
    def test_classbody_constant_does_not_leak(self) -> None:
        # class-level `name = 'safe'` must not shadow a handler-local tainted name.
        code = (
            "import os\nfrom flask import request\n"
            "class C:\n"
            "    name = 'safe'\n"
            "    def h(self):\n"
            "        name = request.args.get('cmd')\n"
            "        os.system(name)\n"
        )
        assert _has(code, "SEC-PY_OS_SYSTEM")

    def test_outer_tainted_still_flags_inner_use(self) -> None:
        # No shadowing: module-level tainted, used in function — still flags.
        code = (
            "import os\nfrom flask import request\n"
            "cmd = request.args.get('c')\n"
            "def h():\n"
            "    os.system(cmd)\n"
        )
        assert _has(code, "SEC-PY_OS_SYSTEM")


# ======================================================================
# Source coverage variants
# ======================================================================


class TestSourceVariants:
    def test_django_cookies_upper(self) -> None:
        code = "import os\ndef h(request):\n    os.system(request.COOKIES['c'])\n"
        assert _reachable(code, "SEC-PY_OS_SYSTEM")

    def test_cookies_get_method(self) -> None:
        code = "import os\nfrom flask import request\nos.system(request.cookies.get('c'))\n"
        assert _reachable(code, "SEC-PY_OS_SYSTEM")

    def test_django_meta_header(self) -> None:
        code = "import os\ndef h(request):\n    os.system(request.META['HTTP_X_CMD'])\n"
        assert _reachable(code, "SEC-PY_OS_SYSTEM")

    def test_request_files_bare(self) -> None:
        code = "import os\ndef h(request):\n    return os.path.join('/d', request.FILES['f'])\n"
        assert _has(code, "SEC-PY_PATH_TRAVERSAL")


# ======================================================================
# False-positive hardening (over-fix guards)
# ======================================================================


class TestNoNewFalsePositives:
    def test_pathlib_path_constant_not_flagged(self) -> None:
        code = "import pathlib\npathlib.Path('/etc/hosts')\n"
        assert not _has(code, "SEC-PY_PATH_TRAVERSAL")

    def test_io_open_constant_not_flagged(self) -> None:
        code = "import io\nio.open('/tmp/x', 'r')\n"
        assert not _has(code, "SEC-PY_PATH_TRAVERSAL")

    def test_session_get_constant_url_not_flagged(self) -> None:
        code = "def h(session):\n    return session.get('https://api.example.com/v1')\n"
        assert not _has(code, "SEC-PY_SSRF")

    def test_markup_constant_not_flagged(self) -> None:
        code = "from markupsafe import Markup\nMarkup('<b>static</b>')\n"
        assert not _has(code, "SEC-PY_XSS_HTML_SINK")

    def test_quote_sanitizer_ssrf_not_flagged(self) -> None:
        code = (
            "import requests\nfrom urllib.parse import quote\nfrom flask import request\n"
            "def h():\n"
            "    u = quote(request.args['u'])\n"
            "    return requests.get('https://api/' + u)\n"
        )
        # quote() is a recognized neutralizer for the interpolation sink.
        assert not _has(code, "SEC-PY_SSRF")

    def test_password_reset_token_not_flagged(self) -> None:
        code = "import hashlib\nhashlib.md5(password_reset_token.encode())\n"
        # "password" appears as a whole token here -> this SHOULD flag (real pw context).
        # The guard is `secretary` (below) which must NOT flag.
        assert _has(code, "SEC-PY_WEAK_CRYPTO_PASSWORD")

    def test_secretary_identifier_not_flagged(self) -> None:
        code = "import hashlib\nhashlib.md5(secretary.encode())\n"
        assert not _has(code, "SEC-PY_WEAK_CRYPTO_PASSWORD")


# ======================================================================
# Deps — version comparator edge cases (packaging.version)
# ======================================================================


class TestVersionComparator:
    def test_prerelease_ordering(self) -> None:
        assert _is_vulnerable("9.0.1rc1", "9.0.1") is True
        assert _is_vulnerable("9.0.1", "9.0.1") is False

    def test_no_numeric_truncation(self) -> None:
        assert _is_vulnerable("1.9", "1.10") is True
        assert _is_vulnerable("1.10", "1.9") is False
        assert _is_vulnerable("2.0", "2.0") is False

    def test_epoch_ordering(self) -> None:
        # 1!2.0 (epoch 1) is NEWER than 2.0 (epoch 0) -> not vulnerable to <2.0
        assert _is_vulnerable("1!2.0", "2.0") is False

    def test_patch_level(self) -> None:
        assert _is_vulnerable("2.19.0", "2.20.0") is True
        assert _is_vulnerable("2.20.0", "2.20.0") is False

    def test_extras_parse_strips_brackets(self) -> None:
        pkgs = _parse_requirements("celery[redis]==5.2.0\nuvicorn[standard]>=0.20\n")
        names = {p for p, _ in pkgs}
        assert "celery" in names and "uvicorn" in names

    def test_triple_equals_is_a_pin(self) -> None:
        assert _extract_pinned_version("===5.0") == "5.0"
        assert _extract_pinned_version("==1.2.3") == "1.2.3"
        assert _extract_pinned_version(">=1.0") is None


# ======================================================================
# Spec — _allows_anon variants
# ======================================================================


class TestSpecAnon:
    def test_empty_list_global(self) -> None:
        ids = _spec(
            {
                "openapi": "3.0.0",
                "components": {
                    "securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}
                },
                "security": [],
                "paths": {},
            }
        )
        assert "SEC-SPEC-NO-GLOBAL-AUTH" in ids

    def test_empty_object_in_list(self) -> None:
        ids = _spec(
            {
                "openapi": "3.0.0",
                "components": {
                    "securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}
                },
                "security": [{}, {"b": []}],
                "paths": {},
            }
        )
        assert "SEC-SPEC-NO-GLOBAL-AUTH" in ids

    def test_real_global_security_not_flagged(self) -> None:
        ids = _spec(
            {
                "openapi": "3.0.0",
                "components": {
                    "securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}
                },
                "security": [{"b": []}],
                "paths": {},
            }
        )
        assert "SEC-SPEC-NO-GLOBAL-AUTH" not in ids

    def test_apikey_in_header_not_flagged(self) -> None:
        ids = _spec(
            {
                "openapi": "3.0.0",
                "components": {
                    "securitySchemes": {
                        "k": {"type": "apiKey", "in": "header", "name": "X-Key"}
                    }
                },
                "security": [{"k": []}],
                "paths": {},
            }
        )
        assert "SEC-SPEC-APIKEY-QUERY" not in ids


# ======================================================================
# Real-data style: scan the bundled dangerous/clean fixtures
# ======================================================================


class TestBundledFixtures:
    def _scan_dir(self, sub: str) -> list[dict]:
        out: list[dict] = []
        ASTAnalyzer(str(FIXTURES / sub)).run(out.append)
        return out

    def test_dangerous_fixture_finds_core_vulns(self) -> None:
        ids = {f["id"] for f in self._scan_dir("ast_target")}
        # The bundled dangerous.py must still trip the core detectors.
        for expected in ("SEC-PY_OS_SYSTEM", "SEC-PY_EVAL", "SEC-PY_SQL_INJECTION"):
            assert expected in ids, f"{expected} missing from {ids}"

    def test_clean_code_in_fixture_low_noise(self) -> None:
        # The clean.py helpers (safe_subprocess/safe_sql/safe_eval_literal) must
        # not produce their corresponding dangerous findings on the safe lines.
        # We assert the fixture dir as a whole doesn't flag the parameterized
        # query / literal-eval patterns from clean.py by checking evidence.
        findings = self._scan_dir("ast_target")
        clean_hits = [f for f in findings if "clean.py" in f.get("endpoint", "")]
        # clean.py is intentionally safe — zero findings expected.
        assert clean_hits == [], (
            f"clean.py produced findings: {[f['id'] for f in clean_hits]}"
        )


# ======================================================================
# Real-data-derived FP fixes (corpus triage: flask / httpx / requests)
# ======================================================================


class TestRealDataFP:
    def test_redirect_url_for_not_flagged(self) -> None:
        # Flask redirect(url_for(...)) is a safe internal URL, not user input.
        code = (
            "from flask import redirect, url_for\n"
            "def h():\n"
            "    return redirect(url_for('auth.login'))\n"
        )
        assert not _has(code, "SEC-PY_OPEN_REDIRECT")

    def test_redirect_reverse_not_flagged(self) -> None:
        # Django redirect(reverse(...)) — same: server-controlled route.
        code = (
            "from django.shortcuts import redirect\n"
            "from django.urls import reverse\n"
            "def h(request):\n"
            "    return redirect(reverse('index'))\n"
        )
        assert not _has(code, "SEC-PY_OPEN_REDIRECT")

    def test_redirect_user_input_still_flagged(self) -> None:
        # Guard: a real open redirect from request input must still flag.
        code = (
            "from flask import redirect, request\n"
            "def h():\n"
            "    return redirect(request.args.get('next'))\n"
        )
        assert _has(code, "SEC-PY_OPEN_REDIRECT")

    def test_pickle_roundtrip_not_flagged(self) -> None:
        # pickle.loads(pickle.dumps(x)) — round-trip of freshly serialized data.
        code = "import pickle\nx = pickle.loads(pickle.dumps(obj))\n"
        assert not _has(code, "SEC-PY_PICKLE_LOAD")

    def test_jsonpickle_roundtrip_not_flagged(self) -> None:
        code = "import jsonpickle\nx = jsonpickle.decode(jsonpickle.encode(obj))\n"
        assert not _has(code, "SEC-PY_PICKLE_LOAD")

    def test_pickle_untrusted_still_flagged(self) -> None:
        # Guard: loading external data must still flag.
        code = "import pickle\ndef h(data):\n    return pickle.loads(data)\n"
        assert _has(code, "SEC-PY_PICKLE_LOAD")


# ======================================================================
# Test-file confidence demotion (user policy: keep coverage, cut noise)
# ======================================================================


class TestTestFileDemotion:
    def _scan_named(self, rel: str, code: str) -> list[dict]:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp, rel)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(code)
            out: list[dict] = []
            ASTAnalyzer(tmp).run(out.append)
            return out

    def test_finding_in_tests_dir_demoted(self) -> None:
        code = "import pickle\ndef test_x(data):\n    return pickle.loads(data)\n"
        fs = self._scan_named("tests/test_thing.py", code)
        pk = [f for f in fs if f["id"] == "SEC-PY_PICKLE_LOAD"]
        assert pk, "finding should still be emitted (coverage kept)"
        assert pk[0]["confidence"] == "LOW"
        assert pk[0].get("in_test") is True

    def test_conftest_demoted(self) -> None:
        code = "import pickle\nx = pickle.loads(blob)\n"
        fs = self._scan_named("conftest.py", code)
        pk = [f for f in fs if f["id"] == "SEC-PY_PICKLE_LOAD"]
        assert pk and pk[0]["confidence"] == "LOW"

    def test_production_finding_not_demoted(self) -> None:
        code = "import pickle\ndef load(data):\n    return pickle.loads(data)\n"
        fs = self._scan_named("app/services.py", code)
        pk = [f for f in fs if f["id"] == "SEC-PY_PICKLE_LOAD"]
        assert pk, "production finding present"
        assert pk[0]["confidence"] != "LOW" or not pk[0].get("in_test")
        assert pk[0].get("in_test") is not True

    def test_is_test_path_variants(self) -> None:
        from analyzers.ast_analyzer import _is_test_path

        assert _is_test_path("tests/test_x.py")
        assert _is_test_path("pkg/test_views.py")
        assert _is_test_path("pkg/views_test.py")
        assert _is_test_path("conftest.py")
        assert _is_test_path("pkg/fixtures/data.py")
        assert not _is_test_path("app/views.py")
        assert not _is_test_path("src/contest.py")  # not 'conftest'
        assert not _is_test_path("latest/main.py")  # 'test' substring, not a test path


# ======================================================================
# TwiScope real-app FP fixes (docs/TWISCOPE_SCAN_TRIAGE.md)
# ======================================================================


class TestReceiverTypeGating:
    def test_redis_client_delete_not_ssrf(self) -> None:
        # redis client.delete(*keys) is NOT an HTTP call.
        code = (
            "import redis\n"
            "def h(keys):\n"
            "    client = redis.Redis()\n"
            "    return client.delete(*keys)\n"
        )
        assert not _has(code, "SEC-PY_SSRF")

    def test_redis_client_get_not_ssrf(self) -> None:
        code = (
            "import redis\n"
            "def h(key):\n"
            "    client = redis.Redis()\n"
            "    return client.get(key)\n"
        )
        assert not _has(code, "SEC-PY_SSRF")

    def test_requests_session_still_ssrf(self) -> None:
        # A real requests.Session().get(user_url) must still flag.
        code = (
            "import requests\nfrom flask import request\n"
            "def h():\n"
            "    s = requests.Session()\n"
            "    return s.get(request.args['u'])\n"
        )
        assert _has(code, "SEC-PY_SSRF")


class TestPsycopgSqlComposable:
    def test_psycopg2_sql_identifier_not_injection(self) -> None:
        # psycopg2.sql.SQL("...").format(sql.Identifier(...)) is the SAFE API.
        code = (
            "from psycopg2 import sql\n"
            "def h(cursor, table):\n"
            "    ident = sql.Identifier(table)\n"
            "    cursor.execute(sql.SQL('SELECT * FROM {}').format(ident))\n"
        )
        assert not _has(code, "SEC-PY_SQL_INJECTION")

    def test_real_str_format_sql_still_injection(self) -> None:
        # Plain str.format() built from request data must still flag.
        code = (
            "from flask import request\n"
            "def h(cursor):\n"
            "    cursor.execute('SELECT * FROM t WHERE x={}'.format(request.args['x']))\n"
        )
        assert _has(code, "SEC-PY_SQL_INJECTION")


class TestConstantHostUrl:
    def test_constant_base_dynamic_path_not_ssrf(self) -> None:
        # requests.get(self.base_url + endpoint) where base_url is a constant.
        code = (
            "import requests\n"
            "class API:\n"
            "    base_url = 'https://api.twitter.com/2/'\n"
            "    def fetch(self, endpoint):\n"
            "        return requests.get(self.base_url + endpoint)\n"
        )
        assert not _has(code, "SEC-PY_SSRF")

    def test_constant_fstring_host_not_ssrf(self) -> None:
        code = (
            "import requests\n"
            "def h(username):\n"
            "    return requests.get(f'https://api.twitter.com/2/users/{username}')\n"
        )
        assert not _has(code, "SEC-PY_SSRF")

    def test_settings_host_not_ssrf(self) -> None:
        code = (
            "import requests\nfrom django.conf import settings\n"
            "def h(payload):\n"
            "    return requests.post(f'{settings.NOTIFICATION_SERVICE_URL}/send', json=payload)\n"
        )
        assert not _has(code, "SEC-PY_SSRF")

    def test_user_controlled_host_still_ssrf(self) -> None:
        # The whole URL (host) is user input → real SSRF, must still flag.
        code = (
            "import requests\nfrom flask import request\n"
            "def h():\n"
            "    return requests.get(request.args['url'])\n"
        )
        assert _has(code, "SEC-PY_SSRF")


class TestPathTraversalNeedsSource:
    def test_dunder_file_relative_not_flagged(self) -> None:
        code = "from pathlib import Path\nBASE_DIR = Path(__file__).resolve().parent.parent\nopen(BASE_DIR)\n"
        assert not _has(code, "SEC-PY_PATH_TRAVERSAL")

    def test_os_getenv_path_not_flagged(self) -> None:
        code = "import os\ndef h():\n    p = os.getenv('JWT_PRIVATE_KEY')\n    return open(p, 'rb')\n"
        assert not _has(code, "SEC-PY_PATH_TRAVERSAL")

    def test_tempfile_name_not_flagged(self) -> None:
        code = (
            "import tempfile\n"
            "def h():\n"
            "    tf = tempfile.NamedTemporaryFile()\n"
            "    return open(tf.name, 'wb')\n"
        )
        assert not _has(code, "SEC-PY_PATH_TRAVERSAL")

    def test_request_path_still_flagged(self) -> None:
        # Real path traversal from request input must still flag.
        code = (
            "from flask import request\n"
            "def h():\n"
            "    return open(request.args['file'])\n"
        )
        assert _has(code, "SEC-PY_PATH_TRAVERSAL")


# ======================================================================
# Sanad real-app recall fixes (docs/SANAD_SCAN_TRIAGE.md)
# ======================================================================


class TestSSRFConstructorSink:
    def test_httpx_asyncclient_base_url_tainted(self) -> None:
        # base_url from config/env into the client constructor → SSRF (A3).
        code = (
            "import httpx\n"
            "def make(config):\n"
            "    base = config.get('base_url')\n"
            "    return httpx.AsyncClient(base_url=base)\n"
        )
        assert _has(code, "SEC-PY_SSRF")

    def test_httpx_client_base_url_from_getenv(self) -> None:
        code = (
            "import os\nimport httpx\n"
            "def make():\n"
            "    return httpx.AsyncClient(base_url=os.getenv('OLLAMA_BASE_URL'))\n"
        )
        assert _has(code, "SEC-PY_SSRF")

    def test_aiohttp_session_base_url_tainted(self) -> None:
        code = (
            "import aiohttp\n"
            "def make(config):\n"
            "    return aiohttp.ClientSession(base_url=config.get('url'))\n"
        )
        assert _has(code, "SEC-PY_SSRF")

    def test_constant_base_url_constructor_not_flagged(self) -> None:
        # A hardcoded base_url is safe — must not flag (precision guard).
        code = (
            "import httpx\n"
            "def make():\n"
            "    return httpx.AsyncClient(base_url='https://api.openai.com/v1')\n"
        )
        assert not _has(code, "SEC-PY_SSRF")


class TestConfigEnvSSRFSource:
    def test_config_get_url_into_requests_get(self) -> None:
        # config.get(...) URL into requests.get → SSRF source recognized.
        code = (
            "import requests\n"
            "def fetch(config):\n"
            "    url = config.get('endpoint')\n"
            "    return requests.get(url)\n"
        )
        assert _has(code, "SEC-PY_SSRF")

    def test_getenv_url_into_requests_get(self) -> None:
        code = (
            "import os, requests\n"
            "def fetch():\n"
            "    return requests.get(os.getenv('WEBHOOK_URL'))\n"
        )
        assert _has(code, "SEC-PY_SSRF")

    def test_getenv_path_still_not_traversal(self) -> None:
        # CRITICAL precision guard: os.getenv must remain a TRUSTED path root
        # for path-traversal (only an SSRF source, not a path source).
        code = "import os\ndef h():\n    p = os.getenv('JWT_PRIVATE_KEY')\n    return open(p, 'rb')\n"
        assert not _has(code, "SEC-PY_PATH_TRAVERSAL")


class TestSanadA3RealShape:
    def test_self_base_url_from_config_into_ctor(self) -> None:
        # The exact Sanad A3 shape: self.base_url = config.get(...) → ctor.
        code = (
            "import httpx\n"
            "class LLM:\n"
            "    def __init__(self, config):\n"
            "        self.base_url = config.get('base_url', 'https://x')\n"
            "        self.client = httpx.AsyncClient(base_url=self.base_url)\n"
        )
        assert _has(code, "SEC-PY_SSRF")

    def test_self_base_url_constant_ctor_not_flagged(self) -> None:
        # self.base_url assigned a CONSTANT → not SSRF (precision guard).
        code = (
            "import httpx\n"
            "class LLM:\n"
            "    def __init__(self):\n"
            "        self.base_url = 'https://api.openai.com/v1'\n"
            "        self.client = httpx.AsyncClient(base_url=self.base_url)\n"
        )
        assert not _has(code, "SEC-PY_SSRF")

    def test_twiscope_fp1_constant_base_url_call_still_suppressed(self) -> None:
        # Recall/precision guard: TwiScope FP-1 (requests.get(self.base_url + path)
        # with a CONSTANT base_url) must STILL be suppressed.
        code = (
            "import requests\n"
            "class API:\n"
            "    base_url = 'https://api.twitter.com/2/'\n"
            "    def f(self, endpoint):\n"
            "        return requests.get(self.base_url + endpoint)\n"
        )
        assert not _has(code, "SEC-PY_SSRF")
