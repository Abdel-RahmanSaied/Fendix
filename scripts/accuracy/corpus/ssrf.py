"""SSRF accuracy corpus."""
import requests

from flask import request


def case_01_requests_get_request_arg():
    # EXPECT_TP: requests.get with user-controlled URL
    target_url = request.args.get("url")
    return requests.get(target_url).text


def case_02_requests_post_request_form():
    # EXPECT_TP: requests.post with user-controlled URL
    callback = request.form["callback"]
    return requests.post(callback, json={"ok": True})


def case_03_multi_hop():
    # EXPECT_TP: assignment-hop before sink
    raw = request.args["target"]
    url = "https://" + raw
    return requests.get(url).text


def case_04_constant_url_safe():
    # EXPECT_TN: literal URL, no user input
    return requests.get("https://api.example.com/health").text


def case_05_name_from_scope_safe():
    # EXPECT_TN: URL resolves to constant in scope
    api_url = "https://api.example.com/users"
    return requests.get(api_url).text
