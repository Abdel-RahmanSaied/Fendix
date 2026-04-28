"""Intentionally dangerous Python code for AST analyzer testing."""
import hashlib
import os
import pickle
import subprocess

import requests
import yaml
from flask import redirect, request


def run_user_command(cmd):
    """Run a user-provided command — dangerous."""
    os.system(cmd)  # SEC-PY_OS_SYSTEM


def eval_expression(expr):
    """Evaluate user expression — dangerous."""
    return eval(expr)  # SEC-PY_EVAL


def exec_code(code_str):
    """Execute user code — dangerous."""
    exec(code_str)  # SEC-PY_EVAL (exec)


def subprocess_shell(cmd):
    """Run subprocess with shell=True — dangerous."""
    subprocess.run(cmd, shell=True)  # SEC-PY_SUBPROCESS_SHELL


def sql_injection(cursor, user_id):
    """Build SQL with % formatting — dangerous."""
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)  # SEC-PY_SQL_INJECTION


def sql_injection_fstring(cursor, user_id):
    """Build SQL with f-string — dangerous."""
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # SEC-PY_SQL_INJECTION


def sql_injection_concat(cursor, user_id):
    """Build SQL with + concatenation — dangerous (TASK-087)."""
    cursor.execute("SELECT * FROM users WHERE id = " + str(user_id))  # SEC-PY_SQL_INJECTION


def sql_injection_via_assignment(cursor, user_id):
    """Build SQL via concat into a variable, then execute — TASK-087 multi-step."""
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    cursor.execute(query)  # SEC-PY_SQL_INJECTION (resolved through scope)


def unsafe_pickle(blob):
    """Deserialize untrusted pickle — RCE."""
    return pickle.loads(blob)  # SEC-PY_PICKLE_LOAD


def unsafe_yaml(stream):
    """yaml.load without SafeLoader — RCE."""
    return yaml.load(stream)  # SEC-PY_YAML_UNSAFE_LOAD


def unsafe_yaml_explicit(stream):
    """yaml.unsafe_load is always dangerous."""
    return yaml.unsafe_load(stream)  # SEC-PY_YAML_UNSAFE_LOAD


def store_password(password):
    """Hash a password with MD5 — wrong choice for credentials."""
    return hashlib.md5(password.encode()).hexdigest()  # SEC-PY_WEAK_CRYPTO_PASSWORD


def store_password_sha1(passwd):
    """Hash a password with SHA1 — also wrong."""
    return hashlib.sha1(passwd.encode()).hexdigest()  # SEC-PY_WEAK_CRYPTO_PASSWORD


def open_redirect_handler():
    """Redirect to user-supplied URL — open redirect."""
    target = request.args.get("next")
    return redirect(target)  # SEC-PY_OPEN_REDIRECT (resolved via _references_request_input)


def open_redirect_inline():
    """Redirect inline with request data — open redirect."""
    return redirect(request.args.get("url"))  # SEC-PY_OPEN_REDIRECT


def fetch_user_url(user_url):
    """Fetch a URL the user controls — SSRF."""
    return requests.get(user_url)  # SEC-PY_SSRF


def admin_via_header():
    """Trust a client header for an auth decision — bypass."""
    if request.headers.get("X-Admin") == "true":  # SEC-PY_AUTH_HEADER_TRUST
        return "admin panel"
    return "denied"


def role_via_header():
    """Trust a client header for role check — bypass."""
    if request.headers.get("X-Role"):  # SEC-PY_AUTH_HEADER_TRUST
        return "elevated"
    return "user"


# This is safe — string literal is fine
def safe_eval():
    return eval("1 + 1")


# Safe parameterized query
def safe_sql(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))


def safe_yaml(stream):
    """yaml.load with SafeLoader is OK."""
    return yaml.load(stream, Loader=yaml.SafeLoader)


def safe_yaml_helper(stream):
    """yaml.safe_load is OK (and not flagged because it's a different attribute)."""
    return yaml.safe_load(stream)


def safe_md5_for_checksum(data):
    """MD5 for a non-password file checksum is fine — variable name has no password hint."""
    return hashlib.md5(data).hexdigest()


def safe_redirect():
    """Redirect to a fixed allow-listed path."""
    return redirect("/dashboard")


def safe_requests_constant():
    """requests.get with a constant URL is fine."""
    return requests.get("https://api.example.com/health")


def safe_session_check():
    """Auth based on a verified session, not a client header — fine."""
    if request.session.get("user_id"):
        return "ok"
    return "denied"
