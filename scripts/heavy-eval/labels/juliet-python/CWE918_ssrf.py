"""CWE-918: SSRF."""
from __future__ import annotations

import urllib.request
import requests
from flask import request, Flask

app = Flask(__name__)


@app.route("/bad01")
def bad_01_requests_get():
    url = request.args.get("url")
    return requests.get(url).text  # SINK


@app.route("/bad02")
def bad_02_urllib_urlopen():
    url = request.args.get("url")
    return urllib.request.urlopen(url).read()  # SINK


@app.route("/bad03")
def bad_03_multi_hop():
    raw = request.args.get("url")
    intermediate = raw
    final = intermediate
    return requests.get(final).text  # SINK


@app.route("/bad04")
def bad_04_requests_post():
    url = request.args.get("url")
    return requests.post(url, json={"x": 1}).text  # SINK


@app.route("/good01")
def good_01_constant():
    return requests.get("https://example.com/healthz").text  # SAFE


@app.route("/good02")
def good_02_whitelist():
    target = request.args.get("target")
    allowed = {
        "stripe": "https://api.stripe.com",
        "github": "https://api.github.com",
    }
    base = allowed.get(target)
    if base is None:
        return "", 400
    return requests.get(base + "/ping").text  # SAFE — whitelisted base


@app.route("/good03")
def good_03_path_only():
    path = request.args.get("path", "")
    return requests.get("https://api.internal/" + path).text  # SAFE? — concat onto constant host
