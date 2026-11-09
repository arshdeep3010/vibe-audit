"""Phase 4 — dynamic analysis in a Docker sandbox.

The target app is executed ONLY inside a container — the single place untrusted code runs. We:
  1. stage a filtered copy of the project (no node_modules/.git/build),
  2. start a locked-down container (memory/cpu/pids caps, port bound to 127.0.0.1 only),
  3. copy the code in and trigger install -> build -> start,
  4. capture build/boot failures from `docker logs`, HTTP-probe the server, and — when Playwright
     is installed — drive headless Chromium to capture browser console errors / uncaught exceptions,
  5. tear the container down.

Every step degrades gracefully: no Docker daemon, an undetectable run command, an oversized repo,
or any error yields an empty finding list plus a log note, never a broken scan. The host only runs
the `docker` CLI and (optionally) a local browser pointed at 127.0.0.1; it never executes repo code.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from app.config import settings
from app.ingest.repomap import Repo
from app.models.findings import Category, Finding, Severity, Source, Verdict

_STAGE_IGNORE = shutil.ignore_patterns(
    "node_modules", ".git", "dist", "build", "out", ".next", ".nuxt", ".svelte-kit",
    "venv", ".venv", "__pycache__", ".turbo", "coverage", ".cache",
)


@dataclass
class RunPlan:
    kind: str            # "node" | "python"
    base_image: str
    install: str
    build: str           # may be ""
    start: str
    container_port: int
    note: str = ""


@dataclass
class DynamicResult:
    findings: list[Finding] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)  # progress lines for the caller to emit


# --------------------------------------------------------------------------- #
# Public entry point (runs in a worker thread; must not touch the async progress queue)
# --------------------------------------------------------------------------- #
def run_dynamic(repo: Repo, scan_id: str) -> DynamicResult:
    res = DynamicResult()
    if not settings.enable_dynamic:
        res.logs.append("Dynamic analysis disabled (ENABLE_DYNAMIC=false).")
        return res
    if not is_docker_available():
        res.logs.append("Docker daemon not reachable - skipping dynamic analysis "
                        "(start Docker Desktop to enable it).")
        return res
    plan = detect_runtime(repo)
    if plan is None:
        res.logs.append("Could not determine how to run this app - skipping dynamic analysis.")
        return res

    name = f"vibeaudit_{scan_id}"
    stage: Path | None = None
    try:
        stage = _stage_copy(repo)
        if stage is None:
            res.logs.append("Project too large to copy into the sandbox - skipping dynamic analysis.")
            return res

        host_port = _free_port()
        res.logs.append(f"Dynamic: {plan.kind} app, image {plan.base_image}, start `{plan.start}`.")

        if not _start_container(name, plan, host_port):
            res.logs.append("Failed to start the sandbox container — skipping dynamic analysis.")
            return res

        # Copy code in, then trigger the install/build/start chain (which becomes the log stream).
        cp = _run(["docker", "cp", f"{stage}/app/.", f"{name}:/app"], timeout=120)
        if cp is None or cp.returncode != 0:
            res.logs.append("Failed to copy project into the sandbox — skipping dynamic analysis.")
            return res
        _run(["docker", "exec", name, "sh", "-lc", "touch /tmp/.start"], timeout=20)

        res.findings = _probe(name, host_port, plan, res)
    except Exception as e:  # noqa: BLE001 - dynamic analysis must never break the scan
        res.logs.append(f"Dynamic analysis error: {e}")
    finally:
        _run(["docker", "rm", "-f", name], timeout=30)
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)
    return res


# --------------------------------------------------------------------------- #
# Docker availability + container lifecycle
# --------------------------------------------------------------------------- #
def is_docker_available() -> bool:
    p = _run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=12)
    return bool(p and p.returncode == 0 and p.stdout.strip())


def _start_container(name: str, plan: RunPlan, host_port: int) -> bool:
    # PID 1 waits for a sentinel, then runs the chain so its output is captured by `docker logs`.
    inner = (
        "mkdir -p /app; "
        "while [ ! -f /tmp/.start ]; do sleep 0.2; done; "
        f"cd /app && {_chain(plan)}"
    )
    cmd = [
        "docker", "run", "-d", "--name", name,
        f"--memory={settings.dynamic_memory}", f"--cpus={settings.dynamic_cpus}",
        "--pids-limit=512",
        "-p", f"127.0.0.1:{host_port}:{plan.container_port}",
        "-w", "/app", plan.base_image, "sh", "-lc", inner,
    ]
    p = _run(cmd, timeout=60)
    return bool(p and p.returncode == 0)


def _chain(plan: RunPlan) -> str:
    return " && ".join(c for c in (plan.install, plan.build, plan.start) if c)


# --------------------------------------------------------------------------- #
# Probing
# --------------------------------------------------------------------------- #
def _probe(name: str, host_port: int, plan: RunPlan, res: DynamicResult) -> list[Finding]:
    deadline = time.time() + settings.dynamic_timeout_s
    served = False
    while time.time() < deadline:
        running, code = _container_state(name)
        if not running and code is not None:
            # The install/build/start chain exited before serving → build or boot failure.
            finding = _classify_exit(_logs(name), code, plan)
            res.logs.append("App exited before serving a request (build/boot failure).")
            return [finding] if finding else []
        if _http_status(host_port, "/") is not None:
            served = True
            break
        time.sleep(2)

    if not served:
        res.logs.append("App did not serve a request within the time budget.")
        f = _classify_exit(_logs(name), None, plan, timed_out=True)
        return [f] if f else []

    res.logs.append("App booted and served a request; probing routes.")
    findings: list[Finding] = []
    for path in ("/", "/api", "/health"):
        status = _http_status(host_port, path)
        if status is not None and status >= 500:
            findings.append(_finding(
                f"Server returns HTTP {status} on {path}", Category.logic, Severity.high,
                f"A request to {path} returned a {status} server error at runtime.",
                "Server-side error responses indicate an unhandled exception or misconfiguration.",
            ))

    findings += _runtime_log_findings(_logs(name))
    if settings.enable_browser_probe:
        findings += _browser_probe(host_port, res)
    return findings


def _browser_probe(host_port: int, res: DynamicResult) -> list[Finding]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        res.logs.append("Playwright not installed - skipping browser console probe.")
        return []

    url = f"http://127.0.0.1:{host_port}/"
    page_errors: list[str] = []
    console_errors: list[str] = []
    failed: list[str] = []
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page()
            page.on("pageerror", lambda e: page_errors.append(str(e)))
            page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
            page.on("requestfailed", lambda r: failed.append(r.url))
            page.goto(url, wait_until="networkidle", timeout=20000)
            page.wait_for_timeout(1500)
            browser.close()
    except Exception as e:  # noqa: BLE001 - missing browser binary, nav timeout, etc.
        res.logs.append(f"Browser probe skipped: {e}")
        return []

    findings: list[Finding] = []
    for msg in page_errors[:5]:
        findings.append(_finding(
            f"Uncaught exception in the browser: {msg[:120]}", Category.logic, Severity.high,
            msg[:500], "An uncaught exception breaks the page for real users.",
        ))
    for msg in console_errors[:5]:
        findings.append(_finding(
            f"Console error at runtime: {msg[:120]}", Category.logic, Severity.medium,
            msg[:500], "Console errors usually signal broken functionality or failed requests.",
        ))
    for url_ in failed[:5]:
        findings.append(_finding(
            f"Failed network request: {url_[:120]}", Category.logic, Severity.medium,
            f"The page requested {url_} and it failed.",
            "A failed request means a missing asset or a broken API call.",
        ))
    res.logs.append(f"Browser probe: {len(findings)} runtime issue(s).")
    return findings


# --------------------------------------------------------------------------- #
# Runtime-detection (pure, unit-testable)
# --------------------------------------------------------------------------- #
def detect_runtime(repo: Repo) -> RunPlan | None:
    files = {sf.rel: sf for sf in repo.files}
    if "package.json" in files:
        return _node_plan(files)
    if "requirements.txt" in files or "pyproject.toml" in files or any(
        r.endswith(".py") for r in files
    ):
        return _python_plan(files)
    return None


def _node_plan(files: dict) -> RunPlan:
    try:
        data = json.loads(files["package.json"].text)
    except (json.JSONDecodeError, ValueError):
        data = {}
    scripts = data.get("scripts", {}) or {}
    deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
    install = "npm ci" if "package-lock.json" in files else "npm install --no-audit --no-fund"
    build = "npm run build" if "build" in scripts else ""

    start, port = "", 3000
    if "vite" in deps:
        if "preview" in scripts:
            start, port = "npm run preview -- --host 0.0.0.0 --port 4173", 4173
        else:
            start, port = "npm run dev -- --host 0.0.0.0 --port 5173", 5173
    elif "next" in deps:
        start = "npm run start -- -H 0.0.0.0 -p 3000" if ("start" in scripts and build) \
            else "npm run dev -- -H 0.0.0.0 -p 3000"
        port = 3000
    if not start:
        for cand in ("start", "serve", "dev", "preview"):
            if cand in scripts:
                start, port = f"npm run {cand}", 3000
                break
    if not start:
        start = f"node {data.get('main', 'index.js')}"
    return RunPlan("node", settings.dynamic_node_image, install, build, start, port,
                   note=str(data.get("name", "")))


def _python_plan(files: dict) -> RunPlan:
    if "requirements.txt" in files:
        install = "pip install --no-cache-dir -r requirements.txt"
    elif "pyproject.toml" in files:
        install = "pip install --no-cache-dir ."
    else:
        install = ""

    py = {r: sf for r, sf in files.items() if r.endswith(".py")}
    blob = "\n".join(sf.text for sf in py.values())[:20000]

    if "manage.py" in files:
        start, port = "python manage.py runserver 0.0.0.0:8000", 8000
    elif "streamlit" in blob:
        entry = _first_py(py, ("app.py", "main.py", "streamlit_app.py")) or "app.py"
        start, port = f"streamlit run {entry} --server.address 0.0.0.0 --server.port 8501", 8501
    elif "FastAPI(" in blob:
        mod = _module_defining(py, "FastAPI(") or "main"
        start, port = f"uvicorn {mod}:app --host 0.0.0.0 --port 8000", 8000
    elif "Flask(" in blob:
        entry = _first_py(py, ("app.py", "main.py", "server.py")) or "app.py"
        start, port = f"flask --app {entry[:-3]} run --host 0.0.0.0 --port 5000", 5000
    else:
        entry = _first_py(py, ("app.py", "main.py", "server.py", "run.py"))
        if not entry:
            return None  # type: ignore[return-value]
        start, port = f"python {entry}", 8000
    return RunPlan("python", settings.dynamic_python_image, install, "", start, port)


def _first_py(py: dict, candidates: tuple[str, ...]) -> str | None:
    for c in candidates:
        if c in py:
            return c
    return next(iter(py), None)


def _module_defining(py: dict, needle: str) -> str | None:
    for rel, sf in py.items():
        if needle in sf.text:
            return rel[:-3].replace("/", ".")
    return None


# --------------------------------------------------------------------------- #
# Log classification (pure, unit-testable)
# --------------------------------------------------------------------------- #
def _classify_exit(logs: str, exit_code: int | None, plan: RunPlan, timed_out: bool = False) -> Finding | None:
    tail = logs.strip()[-1500:]
    low = logs.lower()
    if any(s in low for s in ("error ts", "failed to compile", "build failed", "tsc error",
                              "type error", "cannot find module")):
        return _finding("App fails to build", Category.quality, Severity.high,
                        f"The build step failed.\n\n{tail}",
                        "A failing build means the app cannot ship in its current state.")
    if "traceback (most recent call last)" in low:
        return _finding("App crashes on startup (Python traceback)", Category.logic, Severity.critical,
                        f"The app raised an exception during startup.\n\n{tail}",
                        "The app never starts, so it is completely non-functional.")
    if timed_out:
        return _finding("App never became reachable", Category.logic, Severity.medium,
                        f"No HTTP response within the time budget.\n\n{tail}",
                        "The app may hang on startup, bind the wrong host/port, or need manual steps.")
    return _finding(f"App exited on startup (code {exit_code})", Category.logic, Severity.high,
                    f"The run command exited before serving traffic.\n\n{tail}",
                    "The app does not start cleanly from a fresh checkout.")


def _runtime_log_findings(logs: str) -> list[Finding]:
    if "traceback (most recent call last)" in logs.lower():
        return [_finding("Server logged an exception at runtime", Category.logic, Severity.high,
                         f"A traceback appeared in the server logs while running.\n\n{logs.strip()[-1200:]}",
                         "Runtime exceptions indicate requests are failing for users.")]
    return []


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _finding(title: str, category: Category, severity: Severity, description: str, impact: str) -> Finding:
    return Finding(
        title=title, category=category, severity=severity, file="(runtime)",
        description=description, impact=impact,
        recommendation="Reproduce locally, read the captured log, and fix the underlying error.",
        confidence=0.9, source=Source.dynamic, verdict=Verdict.confirmed,
    )


def _stage_copy(repo: Repo) -> Path | None:
    stage = Path(tempfile.mkdtemp(prefix="vibeaudit_dyn_"))
    dest = stage / "app"
    try:
        shutil.copytree(repo.root, dest, ignore=_STAGE_IGNORE, dirs_exist_ok=True)
    except OSError:
        shutil.rmtree(stage, ignore_errors=True)
        return None
    total = sum(f.stat().st_size for f in dest.rglob("*") if f.is_file())
    if total > settings.dynamic_max_copy_bytes:
        shutil.rmtree(stage, ignore_errors=True)
        return None
    return stage


def _free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _container_state(name: str) -> tuple[bool, int | None]:
    p = _run(["docker", "inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", name], timeout=15)
    if not p or p.returncode != 0:
        return False, None
    parts = p.stdout.split()
    running = len(parts) > 0 and parts[0] == "true"
    code = int(parts[1]) if len(parts) > 1 and parts[1].lstrip("-").isdigit() else None
    return running, (None if running else code)


def _logs(name: str, tail: int = 400) -> str:
    p = _run(["docker", "logs", "--tail", str(tail), name], timeout=25)
    if not p:
        return ""
    return (p.stdout or "") + (p.stderr or "")


def _http_status(port: int, path: str = "/") -> int | None:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError, OSError, ValueError):
        return None


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
