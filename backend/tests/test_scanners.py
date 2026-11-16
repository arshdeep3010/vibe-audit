"""Semgrep: what each mode is allowed to run, how its output becomes findings, and how the
model judges scanner hits (confirm or dismiss, with impact and fix) inside the usual 2 calls."""
from __future__ import annotations

import pytest

from app.analysis import deterministic as det
from app.analysis.deterministic import RULES_DIR, find_semgrep, semgrep_plan, semgrep_status
from app.config import settings
from app.models.findings import Finding, Severity, Source
from tests.conftest import SNIPPET
from tests.test_api import api, paste, wait_done  # noqa: F401 - fixture reuse


@pytest.fixture
def semgrep_on(monkeypatch):
    monkeypatch.setattr(settings, "enable_semgrep", True)


def test_public_mode_never_uses_token_registry_or_pro(semgrep_on, mode, monkeypatch):
    mode("public")
    monkeypatch.setattr(settings, "semgrep_app_token", "tok-should-never-be-used")
    plan = semgrep_plan()
    assert plan.engine == "community" and plan.configs == [str(RULES_DIR)]
    cmd = det._semgrep_cmd("semgrep", plan, "/src", pro=False)
    assert "--pro" not in cmd and "p/default" not in cmd and cmd[cmd.index("--metrics") + 1] == "off"
    assert "SEMGREP_APP_TOKEN" not in det._semgrep_env(pro=False)
    assert semgrep_status()["pro_allowed"] is False


def test_local_mode_adds_registry_and_pro_with_token(semgrep_on, mode, monkeypatch):
    mode("local")
    plan = semgrep_plan()
    assert plan.engine == "community" and "p/default" in plan.configs and "SEMGREP_APP_TOKEN" in plan.note
    monkeypatch.setattr(settings, "semgrep_app_token", "tok")
    plan = semgrep_plan()
    assert plan.engine == "pro" and "Pro rules" in plan.rulesets
    assert det._semgrep_env(pro=True)["SEMGREP_APP_TOKEN"] == "tok"


def test_api_package_ships_the_rule_pack():
    """The API zip must contain backend/rules, or /api/health reports Semgrep as unavailable."""
    src = (RULES_DIR.parents[1] / "infra" / "build_lambda.py").read_text(encoding="utf-8")
    assert '"backend" / "rules"' in src


def test_semgrep_result_becomes_an_unverified_finding():
    f = det._semgrep_finding({
        "check_id": "backend.rules.js-sql-built-from-strings",
        "path": "/tmp/x/server.js",
        "start": {"line": 22}, "end": {"line": 22},
        "extra": {"severity": "ERROR", "message": "SQL text is built\n  by joining strings.",
                  "lines": "const sql = `...${username}`",
                  "metadata": {"title": "SQL query built from strings", "category": "security",
                               "vibeaudit-severity": "critical", "cwe": "CWE-89: SQL Injection",
                               "confidence": "MEDIUM"}},
    }, "/tmp/x")
    assert (f.title, f.severity, f.cwe, f.rule_id, f.file) == (
        "SQL query built from strings", Severity.critical, "CWE-89", "js-sql-built-from-strings", "server.js")
    assert f.source == Source.semgrep and f.verdict.value == "unverified"
    assert f.description == "SQL text is built by joining strings."


def test_failed_pro_scan_falls_back_to_community(semgrep_on, mode, monkeypatch, tmp_path):
    mode("local")
    monkeypatch.setattr(settings, "semgrep_app_token", "tok")
    monkeypatch.setattr(det, "find_semgrep", lambda: "semgrep")
    calls = []

    class Proc:
        def __init__(self, ok):
            self.returncode, self.stdout = (0, '{"results": []}') if ok else (2, "")
            self.stderr = "" if ok else "Semgrep Pro Engine is not installed"

    def fake_run(cmd, env=None, timeout=0):
        calls.append("--pro" in cmd)
        return Proc(ok="--pro" not in cmd)

    monkeypatch.setattr(det, "_run", fake_run)
    repo = type("R", (), {"root": tmp_path, "files": []})()
    findings, note = det._run_semgrep(repo)
    assert calls == [True, False] and findings == []
    assert "Pro unavailable: Semgrep Pro Engine is not installed" in note


def test_model_judges_scanner_hits_within_two_calls(api, monkeypatch):
    def fake_semgrep(repo):
        return [
            Finding(title="SQL query built from strings", category="security", severity="critical",
                    file="server.js", line_start=22, line_end=22, source=Source.semgrep,
                    rule_id="js-sql-built-from-strings", description="SQL built from strings."),
            Finding(title="noise: SQL built from a number", category="security", severity="medium",
                    file="server.js", line_start=90, line_end=90, source=Source.semgrep,
                    rule_id="js-sql-built-from-strings", description="SQL built from strings."),
            # Different lines and CWE, so only the judge's duplicate_of can merge it.
            Finding(title="dup: tainted database call", category="security", severity="low",
                    file="server.js", line_start=30, line_end=30, source=Source.semgrep, cwe="CWE-943",
                    rule_id="express-mysql-sqli", description="Untrusted input reaches a query."),
        ], "semgrep (community engine; VibeAudit rules): 3 finding(s)"

    monkeypatch.setattr(det, "_run_semgrep", fake_semgrep)
    res = wait_done(api, paste(api).json()["scan_id"])
    assert api.fake.calls == ["analyze", "verify_batch"]          # still 2 model calls
    assert "(scanner: semgrep rule js-sql-built-from-strings)" in api.fake.last_verify

    # The scanner's SQL hit and the model's own SQL finding on line 22 become one finding.
    sql = next(f for f in res["findings"] if f["line_start"] == 22 and f["category"] == "security")
    assert sql["source"] == "llm" and sql["corroborated_by"] == ["semgrep"]
    assert sql["rule_id"] == "js-sql-built-from-strings" and sql["verdict"] == "confirmed"

    # The hit the model judged false is kept out of the grade but listed with its reason.
    assert [d["title"] for d in res["dismissed"]] == ["noise: SQL built from a number"]
    assert res["dismissed"][0]["judge_note"] == "Only a constant reaches it."
    assert res["counts"]["scanner_dismissed"] == 1
    assert res["counts"]["dropped_false_positives"] == 1      # the model's own "Speculative issue"
    assert res["counts"]["merged_duplicates"] == 2            # both semgrep SQL hits joined the model's
    assert not any(f["title"].startswith("dup:") for f in res["findings"])
    assert all("duplicate_of" not in f for f in res["findings"])   # internal only
    assert any("semgrep (community engine" in line for line in res["log"])


def test_different_weaknesses_on_the_same_lines_stay_separate():
    from app.analysis.aggregate import aggregate

    sqli = Finding(title="SQL injection in /login", category="security", severity="critical",
                   file="a.js", line_start=22, line_end=22, cwe="CWE-89", verdict="confirmed")
    secret = Finding(title="JWT signed with a hard-coded secret", category="security", severity="high",
                     file="a.js", line_start=9, line_end=25, cwe="CWE-798", source=Source.semgrep)
    same = Finding(title="SQL query built from strings", category="security", severity="critical",
                   file="a.js", line_start=22, line_end=22, cwe="CWE-89", source=Source.semgrep,
                   rule_id="js-sql-built-from-strings")
    out = aggregate([sqli, secret, same])
    assert len(out["findings"]) == 2 and out["merged"] == 1
    merged = next(f for f in out["findings"] if f.cwe == "CWE-89")
    assert (merged.line_start, merged.line_end, merged.corroborated_by) == (22, 22, ["semgrep"])

    # Same bug, different CWE labels: a shared title keyword still merges them.
    llm = Finding(title="Broken async/await in checkout: forEach doesn't wait", category="logic",
                  severity="high", file="a.js", line_start=63, line_end=66, cwe="CWE-833")
    rule = Finding(title="async callback inside forEach is never awaited", category="logic",
                   severity="high", file="a.js", line_start=63, line_end=63, cwe="CWE-362",
                   source=Source.semgrep)
    assert len(aggregate([llm, rule])["findings"]) == 1


def test_long_semgrep_match_points_at_its_first_line():
    f = det._semgrep_finding({"check_id": "x.js-jwt-hardcoded-secret", "path": "/r/a.js",
                              "start": {"line": 9}, "end": {"line": 25},
                              "extra": {"lines": "const JWT_SECRET = \"s\";\n...\njwt.sign(p, JWT_SECRET)"}}, "/r")
    assert (f.line_start, f.line_end, f.code_snippet) == (9, 9, 'const JWT_SECRET = "s";')


@pytest.mark.skipif(find_semgrep() is None, reason="semgrep is not installed")
def test_rule_pack_catches_the_sample_bugs(semgrep_on, mode, tmp_path):
    from app.ingest.repomap import build_repo

    mode("public")
    (tmp_path / "server.js").write_text(SNIPPET, encoding="utf-8")
    findings, note = det._run_semgrep(build_repo(tmp_path))
    rules = {f.rule_id for f in findings}
    assert {"js-sql-built-from-strings", "js-command-injection", "js-reflected-xss",
            "js-jwt-decode-without-verify", "js-async-foreach"} <= rules, note
