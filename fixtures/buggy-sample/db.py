"""Tiny data-access helper — intentionally buggy sample for testing VibeAudit."""
import sqlite3
import subprocess

DB_PASSWORD = "admin"  # hardcoded secret

conn = sqlite3.connect("app.db")


def find_user(username):
    # SQL injection via f-string interpolation.
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cur.fetchone()


def run_backup(filename):
    # Command injection: user input passed to a shell.
    subprocess.call("tar czf /backups/" + filename + " /data", shell=True)


def read_config(path):
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        pass  # silently swallows every error, returns None


def divide_all(numbers, divisor):
    # No guard against divisor == 0.
    return [n / divisor for n in numbers]
