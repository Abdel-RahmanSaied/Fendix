"""CWE-22: Path traversal."""
from __future__ import annotations

import os
from pathlib import Path
from flask import request, send_file, send_from_directory, Flask

app = Flask(__name__)


@app.route("/bad01")
def bad_01_open_request():
    fname = request.args.get("file")
    with open(fname) as f:  # SINK
        return f.read()


@app.route("/bad02")
def bad_02_pathlib():
    fname = request.args.get("file")
    return Path(fname).read_text()  # SINK


@app.route("/bad03")
def bad_03_send_file():
    fname = request.args.get("file")
    return send_file(fname)  # SINK


@app.route("/bad04")
def bad_04_send_from_directory():
    fname = request.args.get("file")
    return send_from_directory("/uploads", fname)  # SINK


@app.route("/bad05")
def bad_05_multi_hop():
    raw = request.args.get("file")
    intermediate = raw
    target = "/var/data/" + intermediate
    return open(target).read()  # SINK


@app.route("/bad06")
def bad_06_os_path_join_user():
    fname = request.args.get("file")
    return open(os.path.join("/var", fname)).read()  # SINK


@app.route("/good01")
def good_01_basename():
    fname = request.args.get("file")
    safe = os.path.basename(fname)
    _ = safe  # ORM would use this; pattern shows the sanitiser
    return open("/uploads/known.txt").read()  # SAFE — constant


@app.route("/good02")
def good_02_whitelist():
    name = request.args.get("name")
    allowed = {"alpha": "/uploads/alpha.txt", "beta": "/uploads/beta.txt"}
    return open(allowed.get(name, "/dev/null")).read()  # SAFE — whitelisted


@app.route("/good03")
def good_03_constant():
    return open("/etc/motd").read()  # SAFE — no user input
