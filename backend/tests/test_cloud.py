"""The Lambda runtime against mocked AWS (moto): DynamoDB store, shared limits, running-scan
slots, the API → worker hand-off, polling progress, the origin check and the SSM key."""
from __future__ import annotations

import time

import boto3
import pytest
from fastapi.testclient import TestClient

moto = pytest.importorskip("moto")

from app import cloud, jobs, main  # noqa: E402
from app.config import settings  # noqa: E402
from app.limits import ScanRejected  # noqa: E402
from app.models.findings import ScanInputMeta, ScanResult  # noqa: E402
from tests.conftest import SNIPPET, FakeLLM  # noqa: E402

TABLE = "vibeaudit-test"


@pytest.fixture
def aws(monkeypatch, mode):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with moto.mock_aws():
        boto3.client("dynamodb").create_table(
            TableName=TABLE, BillingMode="PAY_PER_REQUEST",
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        )
        cloud._table.cache_clear()
        mode("public")
        monkeypatch.setattr(settings, "runtime", "lambda")
        monkeypatch.setattr(settings, "table_name", TABLE)
        yield
        cloud._table.cache_clear()


@pytest.fixture
def lam(aws, monkeypatch):
    """TestClient wired like the Lambda API function; the worker runs when the test says so."""
    from app import lambda_handler

    fake = FakeLLM()
    queued: list[dict] = []
    monkeypatch.setattr(main, "get_llm", lambda: fake)
    monkeypatch.setattr(jobs, "get_llm", lambda: fake)
    monkeypatch.setattr(main, "backend", cloud)
    monkeypatch.setattr(main, "limiter", cloud.DynamoLimiter(per_hour=5, per_day=100))
    monkeypatch.setattr(cloud, "invoke_worker", queued.append)
    with TestClient(main.app) as client:
        client.fake, client.queued = fake, queued
        client.run_worker = lambda: [lambda_handler.worker(queued.pop(0), None) for _ in list(queued)]
        yield client


def paste(client, code=SNIPPET, filename="server.js"):
    return client.post("/api/scan", json={"kind": "paste", "value": code, "filename": filename})


def test_report_round_trip_and_expiry(aws, monkeypatch):
    r = ScanResult(input=ScanInputMeta(kind="paste", name="a.js"), status="done")
    cloud.save(r, "hash1")
    assert cloud.load(r.scan_id).scan_id == r.scan_id
    assert cloud.find_cached("hash1") == r.scan_id
    later = time.time() + settings.result_ttl_hours * 3600 + 5
    monkeypatch.setattr(cloud, "_now", lambda: int(later))
    assert cloud.load(r.scan_id) is None and cloud.find_cached("hash1") is None


def test_incomplete_reports_are_not_cached(aws):
    r = ScanResult(input=ScanInputMeta(kind="paste", name="a.js"), status="done",
                   counts={"failed_segments": 1})
    cloud.save(r, "hash2")
    assert cloud.find_cached("hash2") is None


def test_limits_are_shared_and_counted_once(aws):
    a = cloud.DynamoLimiter(per_hour=2, per_day=3)
    b = cloud.DynamoLimiter(per_hour=2, per_day=3)   # another Lambda instance, same table
    a.consume("1.1.1.1")
    b.consume("1.1.1.1")
    with pytest.raises(ScanRejected) as e:
        a.consume("1.1.1.1")
    assert e.value.status == 429 and "this hour" in e.value.message
    assert a.remaining_today() == 1                   # the refused request gave its day slot back
    b.consume("2.2.2.2")
    with pytest.raises(ScanRejected) as e:
        b.consume("3.3.3.3")
    assert "today's scan limit" in e.value.message


def test_slots_cap_running_scans_and_expire(aws, monkeypatch):
    monkeypatch.setattr(settings, "max_running_scans", 2)
    cloud.acquire_slot("a")
    cloud.acquire_slot("b")
    with pytest.raises(ScanRejected) as e:
        cloud.acquire_slot("c")
    assert "busy" in e.value.message
    cloud.release_slot("a")
    cloud.acquire_slot("c")
    # a lease left behind by a killed worker frees itself after the scan timeout
    monkeypatch.setattr(cloud, "_now", lambda: int(time.time()) + settings.scan_timeout_s + 300)
    cloud.acquire_slot("d")


def test_api_hands_scan_to_worker_and_browser_polls(lam):
    assert lam.get("/api/health").json()["progress"] == "poll"
    r = paste(lam)
    assert r.status_code == 200 and r.json()["cached"] is False
    scan_id = r.json()["scan_id"]
    assert lam.queued and lam.queued[0]["scan_id"] == scan_id
    assert lam.fake.calls == []                      # the API itself makes no model call

    p = lam.get(f"/api/scan/{scan_id}/progress").json()
    assert p == {"events": [], "next": 0, "done": False}

    lam.run_worker()
    assert lam.fake.calls == ["analyze", "verify_batch"]
    p = lam.get(f"/api/scan/{scan_id}/progress?after=0").json()
    assert p["done"] and p["next"] > 0
    stages = [e["stage"] for e in p["events"]]
    assert "analyze" in stages and stages[-1] == "result"
    res = p["events"][-1]["data"]
    assert res["status"] == "done" and "Speculative issue" not in {f["title"] for f in res["findings"]}

    # incremental polling only returns what's new
    again = lam.get(f"/api/scan/{scan_id}/progress?after={p['next']}").json()
    assert [e["stage"] for e in again["events"]] == ["result"]

    assert lam.get(f"/api/scan/{scan_id}").json()["scan_id"] == scan_id
    assert paste(lam).json() == {"scan_id": scan_id, "cached": True}   # free repeat
    cloud.acquire_slot("x")
    cloud.acquire_slot("y")                          # the worker released its slot


def test_worker_failure_still_finishes_the_job(lam):
    lam.fake.fail = True
    scan_id = paste(lam, code="let a = 1;\n", filename="x.js").json()["scan_id"]
    lam.run_worker()
    p = lam.get(f"/api/scan/{scan_id}/progress").json()
    assert p["done"] and p["events"][-1]["data"]["status"] == "error"


def test_stuck_job_reports_an_error(lam, monkeypatch):
    scan_id = paste(lam).json()["scan_id"]           # worker never runs
    monkeypatch.setattr(cloud, "_now", lambda: int(time.time()) + settings.scan_timeout_s + 600)
    p = lam.get(f"/api/scan/{scan_id}/progress").json()
    assert p["done"] and p["events"][-1]["data"]["status"] == "error"


def test_rate_limit_via_api(lam):
    for i in range(5):
        assert paste(lam, code=f"print({i})", filename="a.py").status_code == 200
        lam.run_worker()
    r = paste(lam, code="print('six')", filename="a.py")
    assert r.status_code == 429 and int(r.headers["Retry-After"]) > 0


def test_client_ip_comes_from_cloudfront_header(lam, monkeypatch):
    monkeypatch.setattr(settings, "client_ip_header", "cloudfront-viewer-address")
    seen = []
    monkeypatch.setattr(main.limiter, "consume", seen.append)
    lam.post("/api/scan", json={"kind": "paste", "value": "x=1", "filename": "a.py"},
             headers={"CloudFront-Viewer-Address": "2001:db8::7:443", "X-Forwarded-For": "6.6.6.6"})
    assert seen == ["2001:db8::7"]


def test_requests_must_come_through_cloudfront(lam, monkeypatch):
    monkeypatch.setattr(settings, "origin_secret", "s3cr3t")
    assert lam.get("/api/health").status_code == 403
    assert lam.get("/api/health", headers={"X-Origin-Verify": "wrong"}).status_code == 403
    assert lam.get("/api/health", headers={"X-Origin-Verify": "s3cr3t"}).status_code == 200


def test_model_key_is_read_from_ssm(aws, monkeypatch):
    from app.llm import client

    monkeypatch.setattr(settings, "nvidia_api_key", "")
    monkeypatch.setattr(settings, "llm_api_key_param", "/vibeaudit/test-key")
    monkeypatch.setattr(client, "_singleton", None)
    assert cloud.load_api_key(force=True) is False          # parameter not created yet
    boto3.client("ssm").put_parameter(Name="/vibeaudit/test-key", Value="nvapi-test", Type="SecureString")
    assert cloud.load_api_key(force=True) is True
    assert settings.nvidia_api_key == "nvapi-test" and client.get_llm().ready


def test_rotated_key_is_picked_up_without_redeploy(aws, monkeypatch):
    from app.llm import client

    monkeypatch.setattr(settings, "nvidia_api_key", "")
    monkeypatch.setattr(settings, "llm_api_key_param", "/vibeaudit/rotate")
    monkeypatch.setattr(client, "_singleton", None)
    ssm = boto3.client("ssm")
    ssm.put_parameter(Name="/vibeaudit/rotate", Value="sk-or-v1-wrong", Type="SecureString")
    assert cloud.load_api_key(force=True)
    ssm.put_parameter(Name="/vibeaudit/rotate", Value="nvapi-right", Type="SecureString", Overwrite=True)
    assert cloud.load_api_key() is False                  # checked moments ago: no SSM call
    monkeypatch.setattr(cloud, "_key_checked_at", cloud._key_checked_at - cloud.KEY_REFRESH_S - 1)
    assert cloud.load_api_key() is True and settings.nvidia_api_key == "nvapi-right"
    assert cloud.load_api_key(force=True) is False        # unchanged value: client kept
