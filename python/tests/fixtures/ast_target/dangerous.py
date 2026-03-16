"""Intentionally dangerous Python code for AST analyzer testing."""
import os
import subprocess


def run_user_command(cmd):
    """Run a user-provided command — dangerous."""
    os.system(cmd)  # SEC-PY_OS_SYSTEM


def eval_expression(expr):
    """Evaluate user expression — dangerous."""
    return eval(expr)  # SEC-PY_EVAL


def exec_code(code_str):
    """Execute user code — dangerous."""
    exec(code_str)  # SEC-PY_EVAL (exec)


def subprocess_shell(cmd):
    """Run subprocess with shell=True — dangerous."""
    subprocess.run(cmd, shell=True)  # SEC-PY_SUBPROCESS_SHELL


def sql_injection(cursor, user_id):
    """Build SQL with % formatting — dangerous."""
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)  # SEC-PY_SQL_INJECTION


def sql_injection_fstring(cursor, user_id):
    """Build SQL with f-string — dangerous."""
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # SEC-PY_SQL_INJECTION


# This is safe — string literal is fine
def safe_eval():
    return eval("1 + 1")


# Safe parameterized query
def safe_sql(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
