"""Integration test: route binding attaches to a reachable taint finding."""
from __future__ import annotations

import tempfile
from pathlib import Path

from analyzers.ast_analyzer import ASTAnalyzer


def _scan(files: dict[str, str]) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        for name, content in files.items():
            p = Path(d) / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        findings: list[dict] = []
        ASTAnalyzer(d).run(findings.append)
        return findings


def test_flask_sqli_gets_route_binding():
    app = '''
from flask import Flask, request
import sqlite3
app = Flask(__name__)

@app.route("/users", methods=["GET"])
def list_users():
    uid = request.args.get("id")
    q = "SELECT * FROM users WHERE id = " + uid
    conn = sqlite3.connect("db")
    conn.cursor().execute(q)
'''
    findings = _scan({"app.py": app})
    sqli = [f for f in findings if f.get("reachable") and "route" in f]
    assert sqli, f"expected a reachable finding with a bound route; got {findings}"
    route = sqli[0]["route"]
    assert route["pattern"] == "/users"
    assert route["method"] == "GET"
    assert route["handler"] == "list_users"


def test_django_cross_file_route_binding():
    urls = '''
from django.urls import path
from . import views
urlpatterns = [path("orders/<int:oid>", views.get_order)]
'''
    views = '''
from django.db import connection
def get_order(request, oid):
    raw = request.GET.get("q")
    sql = "SELECT * FROM orders WHERE name = '" + raw + "'"
    connection.cursor().execute(sql)
'''
    findings = _scan({"urls.py": urls, "views.py": views})
    bound = [f for f in findings if "route" in f]
    assert bound, f"expected a route-bound finding across files; got {findings}"
    assert bound[0]["route"]["pattern"] == "orders/<int:oid>"
    assert bound[0]["route"]["handler"] == "views.get_order"


def test_no_route_when_not_a_handler():
    src = '''
from flask import request
def helper():
    x = request.args.get("id")
    __import__("os").system("echo " + x)
'''
    findings = _scan({"util.py": src})
    # A reachable finding may exist, but with no route (helper isn't a handler).
    for f in findings:
        assert "route" not in f, f"non-handler finding must not be route-bound: {f}"
