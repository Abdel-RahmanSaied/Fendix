import requests
from flask import request


def fetch():
    # Real SSRF: request-controlled URL into requests.get (line 7 anchor).
    return requests.get(request.args["url"])


def safe_fetch(path):
    # Constant-authority: host is fixed, only path is dynamic → not SSRF.
    return requests.get("https://api.example.com/" + path)
