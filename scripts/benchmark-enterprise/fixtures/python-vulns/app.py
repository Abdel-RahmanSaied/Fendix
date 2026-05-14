"""Fendix enterprise-benchmark Python fixture.

Each function below is either a labeled TRUE-POSITIVE (a real vulnerability
that all three competing tools should ideally flag) or a TRUE-NEGATIVE
(a safe pattern that LOOKS similar to a TP and is a known false-positive
risk).

Lines are deliberately stable: when you edit this file, update the
manifest.json line numbers in lockstep. The benchmark runner asserts
TP/FP counts against the manifest, so a silent line-number drift would
silently change the score.
"""

import os
import sqlite3
from urllib.parse import urlparse

from flask import Flask, redirect, request, url_for

app = Flask(__name__)

# ---------------------------------------------------------------------------
# TRUE POSITIVES — labeled vulnerabilities
# ---------------------------------------------------------------------------

# TP-1: SQL injection via string concatenation (CWE-89). Line 28.
def sql_lookup_unsafe(user_id):
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = " + str(user_id))
    return cur.fetchall()


# TP-2: Hardcoded AWS access key (CWE-798). Line 35.
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # 20-char AKIA-prefixed


# TP-3: Path traversal via unfiltered user input (CWE-22). Line 41.
def read_user_file(name):
    with open(f"/srv/uploads/{name}", "r") as f:
        return f.read()


# TP-4: SSRF via fully-user-controlled URL (CWE-918). Line 47.
def fetch_url(url):
    import requests
    return requests.get(url).text


# TP-5: Open redirect via flask.redirect(user_target) (CWE-601). Line 53.
@app.route("/go")
def go():
    target = request.args.get("target", "/")
    return redirect(target)


# ---------------------------------------------------------------------------
# TRUE NEGATIVES — safe-but-similar (false-positive probes)
# ---------------------------------------------------------------------------

# TN-1: Parameterised query — NOT SQL injection. Line 65.
def sql_lookup_safe(user_id):
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchall()


# TN-2: AWS key loaded from env — NOT a hardcoded secret. Line 72.
AWS_KEY_FROM_ENV = os.environ.get("AWS_ACCESS_KEY_ID", "")


# TN-3: Path traversal mitigated by basename() — NOT path traversal. Line 76.
def read_user_file_safe(name):
    safe_name = os.path.basename(name)
    with open(os.path.join("/srv/uploads", safe_name), "r") as f:
        return f.read()


# TN-4: SSRF mitigated by whitelist — NOT SSRF. Line 84.
ALLOWED_HOSTS = {"api.example.com", "api.partner.example"}


def fetch_url_safe(url):
    import requests
    host = urlparse(url).hostname or ""
    if host not in ALLOWED_HOSTS:
        raise ValueError(f"host {host!r} not allowed")
    return requests.get(url).text


# TN-5: Open redirect mitigated by url_for() (constant). Line 95.
@app.route("/home")
def home_safe():
    return redirect(url_for("go"))
