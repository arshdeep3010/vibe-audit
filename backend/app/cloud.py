"""AWS backend for the Lambda runtime (RUNTIME=lambda).

A Lambda instance is frozen between requests and requests land on different instances, so
nothing can live in process memory. Everything the server keeps in memory or SQLite lives
here in one DynamoDB table instead (partition key `pk`, TTL attribute `expires_at`):

    scan#<id>      a finished report, gzip-compressed JSON          (expires after RESULT_TTL_HOURS)
    cache#<hash>   pointer from a snippet's content hash to a report (expires after CACHE_TTL_HOURS)
    job#<id>       progress events of a running scan, `done` flag    (expires after 1 day)
    rl#<ip>#<hour> per-client hourly counter (IP is hashed)
    day#<date>     global per-UTC-day counter
    slot#<n>       one of MAX_RUNNING_SCANS slots; a lease that expires on its own

The API function validates and rate-limits a request, takes a slot, writes job#<id> and
invokes the worker function asynchronously. The worker runs the scan, appends progress
events, saves the report and frees the slot. The browser polls /api/scan/<id>/progress.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from functools import lru_cache

import boto3
from botocore.exceptions import ClientError

from app.config import settings
from app.limits import ScanRejected
from app.models.findings import ScanResult

log = logging.getLogger("vibeaudit.cloud")

JOB_TTL_S = 86400
_COND_FAILED = "ConditionalCheckFailedException"


@lru_cache
def _table():
    return boto3.resource("dynamodb").Table(settings.table_name)


def _now() -> int:
    return int(time.time())


def _failed_condition(e: ClientError) -> bool:
    return e.response.get("Error", {}).get("Code") == _COND_FAILED


# ---------------------------------------------------------------- reports + cache
# Same function names as app.store, so main.py can use either module.

def init_db() -> None:  # the table is created by Terraform
    return None


def purge_expired() -> int:  # DynamoDB TTL deletes expired items
    return 0


def list_recent(limit: int = 25) -> list[dict]:  # public mode has no shared history
    return []


def _cacheable(result: ScanResult) -> bool:
    return result.status == "done" and not (result.counts or {}).get("failed_segments")


def save(result: ScanResult, content_hash: str | None = None) -> None:
    now = _now()
    ttl_h = settings.result_ttl_hours if settings.result_ttl_hours > 0 else 24 * 30
    blob = gzip.compress(result.model_dump_json().encode("utf-8"))  # items are capped at 400 KB
    _table().put_item(Item={
        "pk": f"scan#{result.scan_id}", "data": blob, "status": result.status,
        "created": now, "expires_at": now + ttl_h * 3600,
    })
    if content_hash and _cacheable(result) and settings.cache_ttl_hours > 0:
        cache_s = min(settings.cache_ttl_hours, ttl_h) * 3600
        _table().put_item(Item={"pk": f"cache#{content_hash}", "scan_id": result.scan_id,
                                "expires_at": now + cache_s})


def load(scan_id: str) -> ScanResult | None:
    item = _table().get_item(Key={"pk": f"scan#{scan_id}"}).get("Item")
    if not item or int(item.get("expires_at", 0)) < _now():  # TTL deletion can lag by hours
        return None
    return ScanResult.model_validate_json(gzip.decompress(bytes(item["data"])))


def find_cached(content_hash: str) -> str | None:
    if not content_hash or settings.cache_ttl_hours <= 0:
        return None
    item = _table().get_item(Key={"pk": f"cache#{content_hash}"}).get("Item")
    if not item or int(item.get("expires_at", 0)) < _now():
        return None
    return item["scan_id"]


# ---------------------------------------------------------------- rate limits

def _counter(pk: str, limit: int, expires_at: int) -> bool:
    """Atomically add 1 to a counter unless it is already at `limit`. True if counted."""
    try:
        _table().update_item(
            Key={"pk": pk},
            UpdateExpression="ADD #n :one SET #exp = :exp",
            ConditionExpression="attribute_not_exists(#n) OR #n < :limit",
            ExpressionAttributeNames={"#n": "n", "#exp": "expires_at"},
            ExpressionAttributeValues={":one": 1, ":limit": limit, ":exp": expires_at},
        )
        return True
    except ClientError as e:
        if _failed_condition(e):
            return False
        raise


class DynamoLimiter:
    """Per-client hourly limit plus a global per-UTC-day cap, shared by every Lambda instance.
    The hour is a fixed clock-hour window (the in-memory limiter uses a rolling hour)."""

    def __init__(self, per_hour: int, per_day: int, clock=time.time) -> None:
        self.per_hour = per_hour
        self.per_day = per_day
        self._clock = clock

    def _day_key(self, now: float) -> str:
        return "day#" + datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%d")

    def remaining_today(self) -> int:
        item = _table().get_item(Key={"pk": self._day_key(self._clock())}).get("Item") or {}
        return max(0, self.per_day - int(item.get("n", 0)))

    def consume(self, client: str) -> None:
        now = int(self._clock())
        tomorrow = (now // 86400 + 1) * 86400
        day_key = self._day_key(now)
        if not _counter(day_key, self.per_day, tomorrow + 86400):
            raise ScanRejected(429, "The demo has reached today's scan limit. "
                                    "Try the sample, or come back tomorrow.",
                               retry_after=max(60, tomorrow - now))
        hour = now // 3600
        who = hashlib.sha256(client.encode("utf-8")).hexdigest()[:32]  # don't store raw IPs
        if not _counter(f"rl#{who}#{hour}", self.per_hour, (hour + 2) * 3600):
            # give the day's slot back: this request won't run
            _table().update_item(Key={"pk": day_key}, UpdateExpression="ADD #n :m",
                                 ExpressionAttributeNames={"#n": "n"}, ExpressionAttributeValues={":m": -1})
            wait = (hour + 1) * 3600 - now + 1
            raise ScanRejected(429, f"You've run {self.per_hour} audits this hour. "
                                    f"Try again in about {max(1, wait // 60)} minute(s).",
                               retry_after=wait)


# ---------------------------------------------------------------- running-scan slots

def acquire_slot(scan_id: str) -> int:
    """Lease one of MAX_RUNNING_SCANS slots for this scan, or raise 429 busy.
    A lease expires by itself after the scan timeout, so a crashed worker can't leak a slot."""
    now = _now()
    lease = now + settings.scan_timeout_s + 120
    for n in range(max(1, settings.max_running_scans)):
        try:
            _table().put_item(
                Item={"pk": f"slot#{n}", "holder": scan_id, "lease": lease, "expires_at": lease},
                ConditionExpression="attribute_not_exists(#pk) OR #lease < :now",
                ExpressionAttributeNames={"#pk": "pk", "#lease": "lease"},
                ExpressionAttributeValues={":now": now},
            )
            return n
        except ClientError as e:
            if not _failed_condition(e):
                raise
    raise ScanRejected(429, "The auditor is busy with other scans. Try again in a minute.", retry_after=30)


def release_slot(scan_id: str) -> None:
    for n in range(max(1, settings.max_running_scans)):
        try:
            _table().delete_item(Key={"pk": f"slot#{n}"}, ConditionExpression="#h = :me",
                                 ExpressionAttributeNames={"#h": "holder"},
                                 ExpressionAttributeValues={":me": scan_id})
            return
        except ClientError as e:
            if not _failed_condition(e):
                raise


# ---------------------------------------------------------------- jobs + progress

def create_job(scan_id: str, name: str) -> None:
    now = _now()
    _table().put_item(Item={"pk": f"job#{scan_id}", "name": name, "events": [], "done": False,
                            "created": now, "expires_at": now + JOB_TTL_S})


def push_event(scan_id: str, ev: dict) -> None:
    _table().update_item(
        Key={"pk": f"job#{scan_id}"},
        UpdateExpression="SET #ev = list_append(if_not_exists(#ev, :empty), :ev)",
        ExpressionAttributeNames={"#ev": "events"},
        ExpressionAttributeValues={":ev": [json.dumps(ev, default=str)], ":empty": []},
    )


def finish_job(scan_id: str) -> None:
    _table().update_item(Key={"pk": f"job#{scan_id}"}, UpdateExpression="SET #d = :t",
                         ExpressionAttributeNames={"#d": "done"}, ExpressionAttributeValues={":t": True})


def job_events(scan_id: str, after: int) -> tuple[list[dict], bool, int] | None:
    """(new events, done, seconds since start), or None for an unknown job."""
    item = _table().get_item(Key={"pk": f"job#{scan_id}"}, ConsistentRead=True).get("Item")
    if not item:
        return None
    events = [json.loads(e) for e in item.get("events", [])[after:]]
    return events, bool(item.get("done")), _now() - int(item.get("created", _now()))


def invoke_worker(payload: dict) -> None:
    """Start the worker without waiting (async invoke; Lambda queues it if it's busy)."""
    boto3.client("lambda").invoke(
        FunctionName=settings.worker_function,
        InvocationType="Event",
        Payload=json.dumps(payload).encode("utf-8"),
    )


# ---------------------------------------------------------------- model key from SSM

_key_checked_at = 0.0
KEY_RETRY_S = 60       # while no key is set
KEY_REFRESH_S = 300    # once a key is set: picks up a rotated key without a redeploy


def load_api_key(force: bool = False) -> bool:
    """Read the model API key from SSM Parameter Store into settings. Re-read every minute
    while it's missing and every 5 minutes after, so setting or rotating the parameter works
    without a redeploy. Returns True if the key changed."""
    global _key_checked_at
    if not settings.llm_api_key_param:
        return False
    wait = KEY_REFRESH_S if settings.configured else KEY_RETRY_S
    if not force and time.monotonic() - _key_checked_at < wait:
        return False
    _key_checked_at = time.monotonic()
    try:
        value = boto3.client("ssm").get_parameter(Name=settings.llm_api_key_param,
                                                  WithDecryption=True)["Parameter"]["Value"]
    except ClientError as e:
        log.warning("model key not available from SSM (%s)", e.response.get("Error", {}).get("Code"))
        return False
    value = value.strip()
    if not value or value.lower() in ("placeholder", "changeme", "set-me") or value == settings.nvidia_api_key:
        return False
    settings.nvidia_api_key = value
    from app.llm import client
    client._singleton = None  # rebuild the client with the key
    return True
