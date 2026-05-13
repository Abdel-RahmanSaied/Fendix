"""CWE-89: SQL injection.

Pattern mirrors NIST Juliet's "bad" / "good" naming for CWE-89.
Bad cases sink user input into cursor.execute() via string concat,
fstring, %, .format, or a chain of assignments. Good cases use
parameterised queries or constant SQL.

Labelled in labels/juliet-python.json — each `bad_NN` is EXPECT_TP,
each `good_NN` is EXPECT_TN.
"""
from __future__ import annotations

import sqlite3
from flask import request, Flask

app = Flask(__name__)
conn = sqlite3.connect(":memory:")


@app.route("/bad01")
def bad_01_concat():
    name = request.args.get("name")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")  # SINK


@app.route("/bad02")
def bad_02_fstring():
    name = request.args.get("name")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")  # SINK


@app.route("/bad03")
def bad_03_percent():
    name = request.args.get("name")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)  # SINK


@app.route("/bad04")
def bad_04_format():
    name = request.args.get("name")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '{}'".format(name))  # SINK


@app.route("/bad05")
def bad_05_multi_hop():
    raw = request.args.get("q")
    intermediate = raw
    query = "SELECT * FROM users WHERE name = '" + intermediate + "'"
    cursor = conn.cursor()
    cursor.execute(query)  # SINK


@app.route("/bad06")
def bad_06_form_field():
    name = request.form["name"]
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")  # SINK


@app.route("/bad07")
def bad_07_json_body():
    payload = request.get_json() or {}
    name = payload.get("name", "")
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE name='{name}'")  # SINK


@app.route("/good01")
def good_01_parameterised():
    name = request.args.get("name")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))  # SAFE


@app.route("/good02")
def good_02_constant():
    cursor = conn.cursor()
    cursor.execute("SELECT count(*) FROM users")  # SAFE


@app.route("/good03")
def good_03_orm_filter():
    name = request.args.get("name")
    _ = name  # noqa: F841 — ORM call would use this safely; pattern: no string-built SQL
    rows = []
    return rows


@app.route("/good04")
def good_04_named_params():
    name = request.args.get("name")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = :name", {"name": name})  # SAFE
