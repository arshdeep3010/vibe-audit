"""Deterministic (non-LLM) scanners.

All scanners here are STATIC — they read or AST-parse code but never execute it, so they are
safe to run on untrusted input on the host:
- built-in secret scanner (always available, pure regex)
- bandit  (Python AST security linter) — used when installed
- semgrep (multi-language static rules)  — used when installed

eslint is intentionally NOT run here: it loads the target repo's own config/plugins, which can
execute attacker-controlled code. It belongs in the Phase 4 Docker sandbox instead.

These produce ground-truth findings (verdict=confirmed) and a set of "hotspot" files to push to
the front of the LLM's queue.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys

from app.ingest.repomap import Repo
from app.models.findings import Category, Finding, Severity, Source, Verdict
from app.util import mask_secrets

# High-precision credential patterns (name, regex, severity). Deliberately narrow to avoid
# false positives — generic "password = ..." style secrets are left to the LLM pass.
_SECRET_RULES: list[tuple[str, re.Pattern[str], Severity]] = [
    ("NVIDIA API key", re.compile(r"nvapi-[A-Za-z0-9_\-]{20,}"), Severity.critical),
    ("Stripe/OpenAI-style secret key", re.compile(r"sk[-_][A-Za-z0-9][A-Za-z0-9_\-]{14,}"), Severity.critical),
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.critical),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"), Severity.critical),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), Severity.high),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), Severity.high),
    ("JSON Web Token", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}"), Severity.medium),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), Severity.critical),
]

_SUBPROCESS_TIMEOUT = 90


def run_deterministic(repo: Repo) -> tuple[list[Finding], set[str]]:
    """Run every available deterministic scanner. Returns (findings, hotspot file paths)."""
    findings: list[Finding] = []
    findings += _scan_secrets(repo)
    findings += _run_bandit(repo)
    findings += _run_semgrep(repo)
    hotspots = {f.file for f in findings}
    return findings, hotspots


# --------------------------------------------------------------------------- #
# Built-in secret scanner
# --------------------------------------------------------------------------- #
def _scan_secrets(repo: Repo, cap: int = 60) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for sf in repo.files:
        for lineno, line in enumerate(sf.text.splitlines(), start=1):
            if len(line) > 2000:  # skip minified blobs
                continue
            for name, pat, sev in _SECRET_RULES:
                if pat.search(line) and (sf.rel, lineno) not in seen:
                    seen.add((sf.rel, lineno))
                    out.append(
                        Finding(
                            title=f"Hardcoded secret: {name}",
                            category=Category.security,
                            severity=sev,
                            file=sf.rel,
                            line_start=lineno,
                            line_end=lineno,
                            code_snippet=mask_secrets(line.strip()[:200]),
                            description=f"A {name} appears hardcoded in source.",
                            impact="Committed credentials can be extracted from the repo or its "
                            "history and used to access the corresponding service.",
                            recommendation="Move the secret to an environment variable or secret "
                            "manager and rotate the exposed value.",
                            confidence=0.95,
                            source=Source.secret_scan,
                            cwe="CWE-798",
                            verdict=Verdict.confirmed,
                        )
                    )
                    break  # one finding per line
            if len(out) >= cap:
                return out
    return out


# --------------------------------------------------------------------------- #
# bandit (Python)
# --------------------------------------------------------------------------- #
_BANDIT_SEV = {"HIGH": Severity.high, "MEDIUM": Severity.medium, "LOW": Severity.low}
_BANDIT_CONF = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}


def _run_bandit(repo: Repo) -> list[Finding]:
    py_files = [sf for sf in repo.files if sf.language == "python"]
    if not py_files:
        return []
    cmd = [sys.executable, "-m", "bandit", "-f", "json", "-q", *[str(sf.abspath) for sf in py_files]]
    proc = _run(cmd)
    if proc is None or not proc.stdout.strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return []

    root = str(repo.root)
    out: list[Finding] = []
    for r in data.get("results", []):
        rel = _relpath(r.get("filename", ""), root)
        cwe = r.get("issue_cwe") or {}
        cwe_id = f"CWE-{cwe['id']}" if isinstance(cwe, dict) and cwe.get("id") else None
        out.append(
            Finding(
                title=f"[bandit {r.get('test_id', '')}] {_first_line(r.get('issue_text', ''))}",
                category=Category.security,
                severity=_BANDIT_SEV.get(str(r.get("issue_severity")).upper(), Severity.low),
                file=rel,
                line_start=r.get("line_number"),
                line_end=r.get("line_number"),
                code_snippet=(r.get("code") or "")[:600] or None,
                description=r.get("issue_text", ""),
                impact="Flagged by bandit's security ruleset.",
                recommendation="Review the flagged pattern; see the bandit test id for guidance.",
                confidence=_BANDIT_CONF.get(str(r.get("issue_confidence")).upper(), 0.6),
                source=Source.bandit,
                cwe=cwe_id,
                verdict=Verdict.confirmed,
            )
        )
    return out


# --------------------------------------------------------------------------- #
# semgrep (multi-language)
# --------------------------------------------------------------------------- #
_SEMGREP_SEV = {"ERROR": Severity.high, "WARNING": Severity.medium, "INFO": Severity.low}


def _run_semgrep(repo: Repo) -> list[Finding]:
    if not shutil.which("semgrep"):
        return []
    cmd = ["semgrep", "scan", "--config", "auto", "--json", "--quiet", str(repo.root)]
    proc = _run(cmd)
    if proc is None or not proc.stdout.strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return []

    root = str(repo.root)
    out: list[Finding] = []
    for r in data.get("results", []):
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        cwe = meta.get("cwe")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None
        cwe_id = str(cwe).split(":")[0].strip() if cwe else None
        out.append(
            Finding(
                title=f"[semgrep] {r.get('check_id', '').split('.')[-1]}",
                category=Category.security,
                severity=_SEMGREP_SEV.get(str(extra.get("severity")).upper(), Severity.low),
                file=_relpath(r.get("path", ""), root),
                line_start=(r.get("start") or {}).get("line"),
                line_end=(r.get("end") or {}).get("line"),
                code_snippet=(extra.get("lines") or "")[:600] or None,
                description=_first_line(extra.get("message", "")),
                impact="Flagged by a semgrep static rule.",
                recommendation=_first_line(extra.get("message", "")),
                confidence=0.75,
                source=Source.semgrep,
                cwe=cwe_id,
                verdict=Verdict.confirmed,
            )
        )
    return out


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _run(cmd: list[str]) -> subprocess.CompletedProcess[str] | None:
    import os

    # Pass our import path on, so `python -m bandit` finds packages that only this process
    # can see (on AWS Lambda they live in /var/task, which a child interpreter doesn't add).
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(p for p in sys.path if p)}
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=_SUBPROCESS_TIMEOUT, check=False, env=env
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _relpath(path: str, root: str) -> str:
    import os

    try:
        return os.path.relpath(path, root).replace("\\", "/")
    except ValueError:
        return path.replace("\\", "/")


def _first_line(text: str) -> str:
    return (text or "").strip().splitlines()[0][:200] if text and text.strip() else ""
