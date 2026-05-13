"""CWE-78: OS command injection.

Bad cases shell out with tainted args via os.system, subprocess(shell=True),
or os.popen. Good cases pass argv lists, hard-coded commands, or whitelisted
constants.
"""
from __future__ import annotations

import os
import subprocess
from flask import request, Flask

app = Flask(__name__)


@app.route("/bad01")
def bad_01_os_system():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)  # SINK


@app.route("/bad02")
def bad_02_subprocess_shell():
    host = request.args.get("host")
    subprocess.run(f"ping -c 1 {host}", shell=True)  # SINK


@app.route("/bad03")
def bad_03_os_popen():
    name = request.args.get("name")
    return os.popen("echo " + name).read()  # SINK


@app.route("/bad04")
def bad_04_subprocess_popen_shell():
    target = request.form["target"]
    subprocess.Popen(f"nslookup {target}", shell=True)  # SINK


@app.route("/bad05")
def bad_05_multi_hop():
    raw = request.args.get("cmd")
    intermediate = raw
    final = "echo " + intermediate
    os.system(final)  # SINK


@app.route("/bad06")
def bad_06_check_output_shell():
    name = request.args.get("name")
    subprocess.check_output(f"ls {name}", shell=True)  # SINK


@app.route("/good01")
def good_01_argv_list():
    host = request.args.get("host")
    subprocess.run(["ping", "-c", "1", host])  # SAFE — no shell


@app.route("/good02")
def good_02_constant():
    os.system("date")  # SAFE — no user input


@app.route("/good03")
def good_03_check_output_list():
    name = request.args.get("name")
    subprocess.check_output(["echo", name])  # SAFE — argv form


@app.route("/good04")
def good_04_popen_constant():
    # Constant string — fendix's _cmdi_arg_is_dangerous should suppress.
    return os.popen("uptime").read()  # SAFE
