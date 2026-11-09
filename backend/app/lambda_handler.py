"""AWS Lambda entry points (RUNTIME=lambda). One deployment package, two functions:

- `api`:    the FastAPI app behind a Lambda function URL (CloudFront routes /api/* here).
- `worker`: runs one scan, invoked asynchronously by `api` with the validated input.
"""
from __future__ import annotations

import asyncio
import logging

from mangum import Mangum

from app import cloud
from app.config import settings
from app.jobs import execute_scan
from app.main import app

log = logging.getLogger("vibeaudit.worker")
logging.getLogger().setLevel(logging.INFO)

cloud.load_api_key(force=True)  # once per cold start; retried later if the parameter is missing

api = Mangum(app, lifespan="off")  # no startup work: DynamoDB TTL replaces the housekeeping task

# One loop for the life of a warm worker: the model client's connection pool is bound to the
# loop it was first used on, and asyncio.run() would close that loop after every invocation.
_loop = asyncio.new_event_loop()


def worker(event: dict, context) -> dict:
    scan_id = event["scan_id"]
    cloud.load_api_key()
    log.info("scan %s started (%s)", scan_id[:8], event.get("kind"))
    try:
        res = _loop.run_until_complete(execute_scan(
            scan_id, event.get("name") or "snippet", event["kind"], event["value"],
            event.get("depth") or "quick", event.get("filename"), event.get("language"),
            event.get("content_hash"),
            push=lambda ev: _push(scan_id, ev),
            save_fn=cloud.save,
        ))
        log.info("scan %s finished: %s, grade %s", scan_id[:8], res.status, res.risk_grade)
        return {"scan_id": scan_id, "status": res.status}
    finally:
        try:
            cloud.finish_job(scan_id)
        finally:
            if settings.public:
                cloud.release_slot(scan_id)


def _push(scan_id: str, ev: dict) -> None:
    try:
        cloud.push_event(scan_id, ev)
    except Exception:  # noqa: BLE001 - progress is best-effort; the report still gets saved
        log.exception("could not record progress for %s", scan_id[:8])
