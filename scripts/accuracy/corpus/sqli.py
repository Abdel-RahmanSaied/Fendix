"""SQL injection accuracy corpus — labeled test cases.

Each numbered case is annotated with the expected fendix verdict:
  EXPECT_TP — engine SHOULD flag this with SEC-PY_SQL_INJECTION or
              SEC-PYTHON_SQL_INJECTION_* (semgrep) or correlated
  EXPECT_TN — safe-shape; engine should NOT flag this

Test cases mirror real-world patterns; manifest.json keys these by
line number.
"""
import sqlite3

from flask import request


def case_01_request_string_concat():
    # EXPECT_TP: classic concat with user input
    cursor = sqlite3.connect(":memory:").cursor()
    user_id = request.args.get("id")
    sql = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(sql)


def case_02_request_fstring():
    # EXPECT_TP: f-string with request var
    cursor = sqlite3.connect(":memory:").cursor()
    user_id = request.args["id"]
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")


def case_03_request_percent_format():
    # EXPECT_TP: % formatting with user input
    cursor = sqlite3.connect(":memory:").cursor()
    name = request.form["name"]
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)


def case_04_request_format_method():
    # EXPECT_TP: .format() with user input
    cursor = sqlite3.connect(":memory:").cursor()
    role = request.json.get("role")
    cursor.execute("SELECT * FROM perms WHERE role = '{}'".format(role))


def case_05_multi_hop_assignment():
    # EXPECT_TP: user input flows through 2 variables to execute
    cursor = sqlite3.connect(":memory:").cursor()
    raw = request.args.get("q")
    sql = "SELECT * FROM products WHERE name = '" + raw + "'"
    cursor.execute(sql)


def case_06_parameterized_safe():
    # EXPECT_TN: parameterized query — the canonical safe form
    cursor = sqlite3.connect(":memory:").cursor()
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))


def case_07_constant_query_safe():
    # EXPECT_TN: literal query, no user input
    cursor = sqlite3.connect(":memory:").cursor()
    cursor.execute("SELECT * FROM config WHERE key = 'app_name'")


def case_08_orm_no_concat_safe():
    # EXPECT_TN: ORM-style filter, no raw SQL
    user_id = request.args.get("id")
    User = type("User", (), {})  # noqa: N806 (mock the ORM)
    User.query = type("Q", (), {"filter_by": lambda **k: None})()
    User.query.filter_by(id=user_id)
