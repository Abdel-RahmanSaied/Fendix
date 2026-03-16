"""Clean Python code — no security issues."""
import subprocess
import os


def safe_subprocess(cmd_list):
    """Safe subprocess call with list args and no shell."""
    return subprocess.run(cmd_list, shell=False, capture_output=True, text=True)


def safe_os_listdir(path):
    """Safe os operation."""
    return os.listdir(path)


def safe_eval_literal():
    """eval with a static string is OK per our rule."""
    return eval("1 + 2")


def safe_sql(cursor, user_id):
    """Parameterized query."""
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
