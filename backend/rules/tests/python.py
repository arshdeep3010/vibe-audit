# Test cases for ../python.yml. "ruleid:" marks a line that must match, "ok:" one that must not.
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess
import time

import jwt
import requests
import yaml
from flask import Flask, redirect, render_template_string, request, send_file
from flask_cors import CORS

app = Flask(__name__)
# ruleid: py-hardcoded-secret-key
app.config["SECRET_KEY"] = "dev-secret-123"
# ruleid: py-cors-any-origin
CORS(app)
# ruleid: py-hardcoded-credential
DB_PASSWORD = "hunter2-prod"
# ok: py-hardcoded-credential
API_KEY = os.environ.get("API_KEY", "")
# ok: py-hardcoded-credential
ADMIN_PASSWORD = "changeme"


@app.route("/user")
def user():
    cur = sqlite3.connect("app.db").cursor()
    uid = request.args.get("id")
    # ruleid: py-sql-built-from-strings
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")
    # ruleid: py-sql-built-from-strings
    cur.execute("SELECT * FROM users WHERE name = '%s'" % request.args["name"])
    # ruleid: py-sql-built-from-strings
    q = "DELETE FROM users WHERE id = " + uid
    cur.execute(q)
    # ok: py-sql-built-from-strings
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
    # ruleid: py-reflected-xss
    return f"<h1>Hello {request.args.get('name')}</h1>"


@app.route("/ping")
def ping():
    host = request.args.get("host")
    # ruleid: py-command-injection, py-shell-true-with-variable
    os.system("ping -c 1 " + host)
    # ruleid: py-command-injection, py-shell-true-with-variable
    subprocess.run(f"nslookup {host}", shell=True)
    # ok: py-command-injection, py-shell-true-with-variable
    subprocess.run(["ping", "-c", "1", host])
    # ok: py-shell-true-with-variable
    subprocess.run("ls -la", shell=True)
    return "ok"


@app.route("/hello")
def hello():
    # ruleid: py-template-injection
    return render_template_string("Hello " + request.args.get("name", ""))


@app.route("/download")
def download():
    # ruleid: py-path-traversal
    return send_file(os.path.join("/srv/files", request.args["f"]))


@app.route("/download-safe")
def download_safe():
    # ok: py-path-traversal
    return send_file(os.path.join("/srv/files", os.path.basename(request.args["f"])))


@app.route("/fetch")
def fetch():
    # ruleid: py-ssrf
    r = requests.get(request.args["url"], timeout=5)
    # ok: py-ssrf
    s = requests.get("https://api.example.com/status", timeout=5)
    return r.text + s.text


@app.route("/next")
def go_next():
    # ruleid: py-open-redirect
    return redirect(request.args.get("next"))


def load_profile(blob, text):
    # ruleid: py-unsafe-deserialization
    data = pickle.loads(blob)
    # ruleid: py-unsafe-deserialization
    cfg = yaml.load(text)
    # ok: py-unsafe-deserialization
    safe = yaml.load(text, Loader=yaml.SafeLoader)
    # ruleid: py-code-eval
    total = eval(text)
    # ok: py-code-eval
    two = eval("1 + 1")
    return data, cfg, safe, total, two


def read_token(token, key):
    # ruleid: py-jwt-signature-not-verified
    claims = jwt.decode(token, options={"verify_signature": False})
    # ok: py-jwt-signature-not-verified
    good = jwt.decode(token, key, algorithms=["HS256"])
    return claims, good


def call_api(url):
    # ruleid: py-tls-verification-disabled
    return requests.get(url, verify=False, timeout=5)


def store_password(password):
    # ruleid: py-weak-password-hash
    return hashlib.md5(password.encode()).hexdigest()


def file_etag(body):
    # ok: py-weak-password-hash
    return hashlib.sha256(body).hexdigest()


def new_reset():
    # ruleid: py-weak-random-token
    reset_token = "".join(random.choice("abcdef0123456789") for _ in range(16))
    # ok: py-weak-random-token
    delay = random.random() * 3
    return reset_token, delay


def save(path, text):
    # ruleid: py-swallowed-exception
    try:
        open(path, "w").write(text)
    except Exception:
        pass
    # ok: py-swallowed-exception
    try:
        open(path, "w").write(text)
    except OSError as e:
        print("could not save", e)


# ruleid: py-mutable-default-argument
def add_item(item, bucket=[]):
    bucket.append(item)
    return bucket


# ok: py-mutable-default-argument
def add_item_safe(item, bucket=None):
    bucket = bucket or []
    bucket.append(item)
    return bucket


async def slow_handler():
    # ruleid: py-blocking-call-in-async
    time.sleep(2)
    # ruleid: py-blocking-call-in-async
    return requests.get("https://example.com", timeout=5)


def sync_ok():
    # ok: py-blocking-call-in-async
    time.sleep(1)


def delete_user(user, target):
    # ruleid: py-assert-for-security
    assert user.is_admin, "admins only"
    # ok: py-assert-for-security
    assert target is not None
    target.delete()


if __name__ == "__main__":
    # ruleid: py-debug-mode-on
    app.run(host="0.0.0.0", debug=True)
