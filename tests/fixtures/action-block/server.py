"""Fixture for the composite Action's BLOCK smoke leg (action-smoke.yml).

A request parameter reaches a shell: fendix v3.6.0 reports a CRITICAL
command-injection finding with status BLOCK, so `--fail-on HIGH` exits 1.
Never deployed; it exists only to be scanned.
"""
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    cmd = request.args.get("cmd", "")
    return subprocess.check_output(cmd, shell=True)
