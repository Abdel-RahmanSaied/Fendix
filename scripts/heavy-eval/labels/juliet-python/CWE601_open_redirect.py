"""CWE-601: Open redirect."""
from __future__ import annotations

from flask import request, redirect, Flask

app = Flask(__name__)


@app.route("/bad01")
def bad_01_direct():
    target = request.args.get("next")
    return redirect(target)  # SINK


@app.route("/bad02")
def bad_02_multi_hop():
    raw = request.args.get("next")
    intermediate = raw
    return redirect(intermediate)  # SINK


@app.route("/bad03")
def bad_03_form_field():
    target = request.form["url"]
    return redirect(target)  # SINK


@app.route("/good01")
def good_01_constant():
    return redirect("/home")  # SAFE


@app.route("/good02")
def good_02_whitelist():
    target = request.args.get("next", "/")
    allowed = {"/home", "/dashboard", "/profile"}
    if target not in allowed:
        return redirect("/")
    return redirect(target)  # SAFE — whitelisted

# NOTE: good_02 is interesting — the engine should not flag this because
# `target` is checked against a constant set before being redirected.
# Whether fendix detects the whitelist is a real reachability test.
