"""Deterministic (non-LLM) scanners.

All scanners here are STATIC — they read or AST-parse code but never execute it, so they are
safe to run on untrusted input on the host:
- built-in secret scanner (always available, pure regex)
- bandit  (Python AST security linter) — used when installed
- semgrep (multi-language rules) — VibeAudit's own rule pack (backend/rules) everywhere; when
  self-hosted also the Registry's p/default, and the Pro engine once SEMGREP_APP_TOKEN is set

eslint is intentionally NOT run here: it loads the target repo's own config/plugins, which can
execute attacker-controlled code. It belongs in the Phase 4 Docker sandbox instead.

Secret-scan hits are high-precision and trusted as-is (verdict=confirmed). bandit and semgrep
hits stay unverified: the model judges each one in the verification pass (confirm or drop, with
impact and fix written for this code). Every hit also marks a "hotspot" file that goes to the
front of the LLM's queue, and is handed to the audit prompt as a hint.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from app.config import PROJECT_ROOT, settings
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


def run_deterministic(repo: Repo) -> tuple[list[Finding], set[str], list[str]]:
    """Run every available deterministic scanner.
    Returns (findings, hotspot file paths, one log line per scanner)."""
    notes: list[str] = []
    secrets = _scan_secrets(repo)
    notes.append(f"secret scan: {len(secrets)} finding(s)")
    bandit = _run_bandit(repo)
    if any(sf.language == "python" for sf in repo.files):
        notes.append(f"bandit: {len(bandit)} finding(s)")
    semgrep, note = _run_semgrep(repo)
    notes.append(note)
    findings = secrets + bandit + semgrep
    return findings, {f.file for f in findings}, notes


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
                rule_id=r.get("test_id") or None,
            )
        )
    return out


# --------------------------------------------------------------------------- #
# semgrep (multi-language)
# --------------------------------------------------------------------------- #
RULES_DIR = Path(__file__).resolve().parents[2] / "rules"   # backend/rules, or /var/task/rules
_SEV = {s.value: s for s in Severity}
_CAT = {c.value: c for c in Category}
_SEMGREP_SEV = {"ERROR": Severity.high, "WARNING": Severity.medium, "INFO": Severity.low}
_SEMGREP_CONF = {"HIGH": 0.85, "MEDIUM": 0.7, "LOW": 0.5}


@dataclass
class SemgrepPlan:
    available: bool
    engine: str             # "pro" | "community" | ""
    rulesets: list[str]     # human-readable names
    configs: list[str]      # --config values
    note: str = ""          # why something is off


def find_semgrep() -> str | None:
    if settings.semgrep_bin:
        b = settings.semgrep_bin
        return b if Path(b).exists() or shutil.which(b) else None
    found = shutil.which("semgrep")
    if found:
        return found
    for rel in (".venv-semgrep/Scripts/semgrep.exe", ".venv-semgrep/bin/semgrep"):
        p = PROJECT_ROOT / rel
        if p.exists():
            return str(p)
    return None


def semgrep_plan() -> SemgrepPlan:
    """What a scan will run. Public mode is locked to the community engine and our own rules
    whatever the environment says: Registry and Pro rules may only be used on your own code,
    not offered to others as a service."""
    if not settings.enable_semgrep:
        return SemgrepPlan(False, "", [], [], "disabled (ENABLE_SEMGREP=false)")
    if not RULES_DIR.is_dir():
        return SemgrepPlan(False, "", [], [], "rule pack missing")
    configs, names = [str(RULES_DIR)], ["VibeAudit rules"]
    if settings.public:
        return SemgrepPlan(True, "community", names, configs,
                           "Pro engine and Registry rules run only when self-hosted")
    if settings.semgrep_registry_config:
        configs.append(settings.semgrep_registry_config)
        names.append(f"Registry {settings.semgrep_registry_config}")
    if settings.semgrep_app_token.strip():
        return SemgrepPlan(True, "pro", names + ["Pro rules"], configs)
    return SemgrepPlan(True, "community", names, configs, "set SEMGREP_APP_TOKEN for the Pro engine")


def semgrep_status() -> dict:
    """For /api/health and the UI. On Lambda only the worker image contains semgrep, so the
    API reports the plan instead of looking for a binary it doesn't have."""
    plan = semgrep_plan()
    installed = settings.serverless or find_semgrep() is not None
    ok = plan.available and installed
    return {
        "available": ok,
        "engine": plan.engine if ok else "",
        "rulesets": plan.rulesets if ok else [],
        "pro_allowed": not settings.public,
        "note": plan.note if installed else "semgrep is not installed",
    }


def _semgrep_cmd(binary: str, plan: SemgrepPlan, root: str, pro: bool) -> list[str]:
    cmd = [binary, "scan", "--json", "--quiet", "--disable-version-check", "--metrics", "off",
           "--timeout", "10", "--max-target-bytes", "1000000"]
    for c in plan.configs:
        cmd += ["--config", c]
    if pro:
        cmd.append("--pro")
    return [*cmd, root]


def _semgrep_env(pro: bool) -> dict:
    env = {k: v for k, v in os.environ.items() if k != "SEMGREP_APP_TOKEN"}
    env.update({"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0", "PYTHONUTF8": "1"})
    if settings.serverless:
        env["HOME"] = "/tmp"   # semgrep writes ~/.semgrep; /tmp is Lambda's only writable folder
    if pro:
        env["SEMGREP_APP_TOKEN"] = settings.semgrep_app_token.strip()
    return env


def _run_semgrep(repo: Repo) -> tuple[list[Finding], str]:
    plan = semgrep_plan()
    if not plan.available:
        return [], f"semgrep: skipped ({plan.note})"
    binary = find_semgrep()
    if not binary:
        return [], "semgrep: skipped (not installed)"

    def scan(pro: bool):
        return _semgrep_json(_run(_semgrep_cmd(binary, plan, str(repo.root), pro),
                                  env=_semgrep_env(pro), timeout=settings.semgrep_timeout_s))

    pro = plan.engine == "pro"
    data, err = scan(pro)
    engine = "Pro engine" if pro else "community engine"
    if pro and data is None:
        # Pro engine not installed (`semgrep install-semgrep-pro`) or token rejected.
        engine = f"community engine; Pro unavailable: {err}"
        data, err = scan(False)
    if data is None:
        return [], f"semgrep: failed ({err})"

    findings = [_semgrep_finding(r, str(repo.root)) for r in data.get("results", [])]
    return findings, f"semgrep ({engine}; {', '.join(plan.rulesets)}): {len(findings)} finding(s)"


def _semgrep_json(proc: subprocess.CompletedProcess[str] | None) -> tuple[dict | None, str]:
    """(parsed output, error). semgrep exits 0 with no findings and 1 with findings."""
    if proc is None:
        return None, "did not start"
    if proc.returncode in (0, 1) and proc.stdout.strip():
        try:
            data = json.loads(proc.stdout)
            if isinstance(data, dict):
                return data, ""
        except (json.JSONDecodeError, ValueError):
            pass
    lines = [ln for ln in (proc.stderr or "").strip().splitlines() if ln.strip()]
    return None, (lines[-1][:160] if lines else f"exit code {proc.returncode}")


def _semgrep_finding(r: dict, root: str) -> Finding:
    extra = r.get("extra", {}) or {}
    meta = extra.get("metadata", {}) or {}
    cwe = meta.get("cwe")
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else None
    rule = str(r.get("check_id", "")).split(".")[-1]
    sev = _SEV.get(str(meta.get("vibeaudit-severity", "")).lower()) or \
        _SEMGREP_SEV.get(str(extra.get("severity")).upper(), Severity.low)
    start = (r.get("start") or {}).get("line")
    end = (r.get("end") or {}).get("line") or start
    if start and end and end - start > 4:
        end = start  # a multi-statement match (secret defined ... used) points at its first line
    return Finding(
        title=str(meta.get("title") or rule.replace("-", " ").replace("_", " "))[:200],
        category=_CAT.get(str(meta.get("category", "")).lower(), Category.security),
        severity=sev,
        file=_relpath(r.get("path", ""), root),
        line_start=start,
        line_end=end,
        code_snippet=mask_secrets((extra.get("lines") or "").splitlines()[0][:300]
                                  if end == start else (extra.get("lines") or "")[:600]) or None,
        description=mask_secrets(" ".join(str(extra.get("message", "")).split()))[:800],
        confidence=_SEMGREP_CONF.get(str(meta.get("confidence", "")).upper(), 0.7),
        source=Source.semgrep,
        cwe=str(cwe).split(":")[0].strip() if cwe else None,
        rule_id=rule or None,
    )


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _run(cmd: list[str], env: dict | None = None,
         timeout: int = _SUBPROCESS_TIMEOUT) -> subprocess.CompletedProcess[str] | None:
    # Pass our import path on, so `python -m bandit` finds packages that only this process
    # can see (on AWS Lambda they live in /var/task, which a child interpreter doesn't add).
    if env is None:
        env = {**os.environ, "PYTHONPATH": os.pathsep.join(p for p in sys.path if p)}
    try:
        return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout, check=False, env=env)
    except (OSError, subprocess.SubprocessError):
        return None


def _relpath(path: str, root: str) -> str:
    try:
        return os.path.relpath(path, root).replace("\\", "/")
    except ValueError:
        return path.replace("\\", "/")


def _first_line(text: str) -> str:
    return (text or "").strip().splitlines()[0][:200] if text and text.strip() else ""
