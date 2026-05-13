"""Command injection accuracy corpus."""
import os
import subprocess

from flask import request


def case_01_os_system_request():
    # EXPECT_TP: os.system with user input
    target = request.args.get("host")
    os.system("ping -c 1 " + target)


def case_02_subprocess_shell_true():
    # EXPECT_TP: subprocess.run with shell=True + user input
    cmd = request.args.get("cmd")
    subprocess.run(cmd, shell=True)


def case_03_os_popen_request():
    # EXPECT_TP: os.popen with user input
    name = request.form["file"]
    return os.popen("cat " + name).read()


def case_04_subprocess_popen_shell_true():
    # EXPECT_TP: subprocess.Popen with shell=True
    user_query = request.json["q"]
    subprocess.Popen(user_query, shell=True)


def case_05_multi_hop():
    # EXPECT_TP: assignment-hop before sink
    raw = request.args["target"]
    cmd_string = "ping -c 1 " + raw
    os.system(cmd_string)


def case_06_subprocess_list_safe():
    # EXPECT_TN: shell=False (default) with argv list
    target = request.args.get("host")
    subprocess.run(["ping", "-c", "1", target])


def case_07_constant_safe():
    # EXPECT_TN: literal cmd, no user input
    os.system("echo hello world")


def case_08_subprocess_check_output_safe():
    # EXPECT_TN: shell=False explicit, list args
    subprocess.check_output(["ls", "-la", "/tmp"], shell=False)
