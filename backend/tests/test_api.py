"""End-to-end API behaviour with a fake model: guards, cost (number of LLM calls), cache,
rate limits, privacy and result expiry."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import jobs, main
from app.config import settings
from app.limits import Limiter
from app.models.findings import ScanInputMeta, ScanResult
from tests.conftest import SNIPPET, FakeLLM


@pytest.fixture
def api(tmp_store, mode, monkeypatch):
    """A TestClient in public mode with a fresh limiter, job table and fake model."""
    mode("public")
    fake = FakeLLM()
    monkeypatch.setattr(main, "get_llm", lambda: fake)
    monkeypatch.setattr(jobs, "get_llm", lambda: fake)
    monkeypatch.setattr(main, "limiter", Limiter(per_hour=5, per_day=100))
    monkeypatch.setattr(main, "manager", jobs.ScanManager())
    with TestClient(main.app) as client:
        client.fake = fake
        yield client


def paste(client, code=SNIPPET, filename="server.js", **extra):
    return client.post("/api/scan", json={"kind": "paste", "value": code, "filename": filename, **extra})


def wait_done(client, scan_id, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        r = client.get(f"/api/scan/{scan_id}")
        if r.status_code == 200 and r.json()["status"] in ("done", "error"):
            return r.json()
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


def test_snippet_scan_uses_two_model_calls(api):
    r = paste(api)
    assert r.status_code == 200 and r.json()["cached"] is False
    scan_id = r.json()["scan_id"]
    assert len(scan_id) == 32                      # unguessable id

    res = wait_done(api, scan_id)
    assert res["status"] == "done"
    # One audit call (profile included) + one batched verification. No triage call.
    assert api.fake.calls == ["analyze", "verify_batch"]
    assert res["triage"]["app_type"] == "Express API"
    titles = {f["title"]: f for f in res["findings"]}
    assert "Speculative issue" not in titles       # dropped by verification
    assert titles["SQL injection in /login"]["verdict"] == "confirmed"
    # deterministic secret scan still runs, and the key is masked in the report
    secret = [f for f in res["findings"] if f["source"] == "secret-scan"]
    assert secret and "sk_live_FAKE_EXAMPLE_KEY_0000" not in json.dumps(res)


def test_identical_snippet_reuses_report_without_quota(api):
    first = paste(api).json()["scan_id"]
    wait_done(api, first)
    calls = len(api.fake.calls)
    remaining = api.get("/api/health").json()["limits"]["remaining_today"]

    again = paste(api)
    assert again.json() == {"scan_id": first, "cached": True}
    assert len(api.fake.calls) == calls             # no new model calls
    assert api.get("/api/health").json()["limits"]["remaining_today"] == remaining

    # a different file name is a different audit
    assert paste(api, filename="other.js").json()["cached"] is False


def test_public_mode_refuses_folders_repos_and_deep(api):
    assert api.post("/api/scan", json={"kind": "local", "value": "C:\\"}).status_code == 403
    assert api.post("/api/scan", json={"kind": "github", "value": "https://github.com/a/b"}).status_code == 403
    assert paste(api, depth="deep").status_code == 403
    assert api.fake.calls == []


def test_rate_limit_returns_429_with_retry_after(api):
    for i in range(5):
        r = paste(api, code=f"print({i})", filename="a.py")
        assert r.status_code == 200
        wait_done(api, r.json()["scan_id"])     # stay under the running-scans cap
    r = paste(api, code="print('six')", filename="a.py")
    assert r.status_code == 429 and int(r.headers["Retry-After"]) > 0
    assert "hour" in r.json()["detail"]


def test_busy_when_too_many_scans_running(api, monkeypatch):
    monkeypatch.setattr(type(main.manager), "running", property(lambda self: settings.max_running_scans))
    r = paste(api, code="print('busy')")
    assert r.status_code == 429 and "busy" in r.json()["detail"]


def test_oversized_requests_are_refused(api):
    huge = "x" * (settings.max_request_bytes + 10)
    assert paste(api, code=huge).status_code == 413
    too_long = "\n".join(["x = 1"] * (settings.max_snippet_lines + 5))
    r = paste(api, code=too_long)
    assert r.status_code == 413 and "lines" in r.json()["detail"]


def test_shared_history_and_docs_are_hidden_in_public_mode(api):
    assert api.get("/api/scans").status_code == 404
    assert api.get("/docs").status_code == 404


def test_how_it_works_page_is_served(api):
    r = api.get("/how-it-works")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert "HOW_STEPS" in r.text and "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_security_headers_are_set(api):
    h = api.get("/api/health").headers
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in h["content-security-policy"]


def test_all_segments_failing_is_an_error_not_a_clean_grade(api):
    api.fake.fail = True
    res = wait_done(api, paste(api, code="let a = 1;\n", filename="x.js").json()["scan_id"])
    assert res["status"] == "error"
    assert "nothing was checked" in res["error"]
    assert res["risk_grade"] != "A"


def test_results_expire_in_public_mode(tmp_store, mode):
    mode("public")
    old = ScanResult(input=ScanInputMeta(kind="paste", name="old.js"), status="done",
                     created_at=(datetime.now(timezone.utc) - timedelta(hours=settings.result_ttl_hours + 1)).isoformat())
    fresh = ScanResult(input=ScanInputMeta(kind="paste", name="new.js"), status="done")
    tmp_store.save(old)
    tmp_store.save(fresh)
    assert tmp_store.load(old.scan_id) is None
    assert tmp_store.load(fresh.scan_id) is not None
    assert tmp_store.purge_expired() == 1


def test_local_mode_keeps_history(tmp_store, mode):
    mode("local")
    r = ScanResult(input=ScanInputMeta(kind="local", name="app"), status="done",
                   created_at=(datetime.now(timezone.utc) - timedelta(days=30)).isoformat())
    tmp_store.save(r)
    assert tmp_store.load(r.scan_id) is not None
    assert tmp_store.purge_expired() == 0
    assert [x["scan_id"] for x in tmp_store.list_recent()] == [r.scan_id]


def test_public_and_local_modes_use_separate_databases():
    """Public-mode expiry must never delete local history (it once did, when they shared a file)."""
    import subprocess
    import sys

    code = "from app import store; print(store.DB_PATH.name)"
    names = {}
    for m in ("local", "public"):
        env = {**__import__("os").environ, "APP_MODE": m}
        names[m] = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                                  env=env, cwd=str(__import__("pathlib").Path(__file__).resolve().parents[1])).stdout.strip()
    assert names == {"local": "vibeaudit.db", "public": "vibeaudit-public.db"}


def test_finished_jobs_are_evicted_from_memory(monkeypatch):
    m = jobs.ScanManager()
    j = jobs.ScanJob("x" * 32, "n")
    j.done, j.finished_at = True, time.monotonic() - settings.job_retention_s - 1
    m.jobs[j.scan_id] = j
    assert m.sweep() == 1 and not m.jobs
