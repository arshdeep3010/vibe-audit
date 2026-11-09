"""In-memory scan job manager: runs scans as background tasks and buffers progress
events so a (possibly late-connecting) SSE client receives the full stream.

Finished jobs are evicted after JOB_RETENTION_S (their results stay in SQLite), so memory
doesn't grow with every scan. Every scan has a hard SCAN_TIMEOUT_S.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Callable

from app.config import settings
from app.ingest import sources
from app.ingest.sources import Workspace
from app.llm.client import get_llm
from app.models.findings import ScanInputMeta, ScanResult
from app.scan import run_scan
from app.store import save

log = logging.getLogger("vibeaudit.jobs")

PING = None  # sentinel yielded by ScanJob.stream() when the client should get a keep-alive


def build_workspace(
    kind: str, value: str, filename: str | None = None, language: str | None = None
) -> Workspace:
    if kind == "local":
        return sources.from_local(value)
    if kind == "github":
        return sources.from_github(value)
    if kind == "paste":
        return sources.from_paste(value, filename=filename, language_hint=language)
    raise ValueError(f"unknown input kind: {kind!r}")


class ScanJob:
    def __init__(self, scan_id: str, name: str) -> None:
        self.scan_id = scan_id
        self.name = name
        self.events: list[dict] = []
        self.result: ScanResult | None = None
        self.done = False
        self.finished_at: float | None = None
        self._new = asyncio.Event()

    def push(self, ev: dict) -> None:
        self.events.append(ev)
        self._new.set()

    def finish(self, result: ScanResult) -> None:
        self.result = result
        self.done = True
        self.finished_at = time.monotonic()
        self._new.set()

    async def stream(self, ping_every: float = 15.0):
        """Yield every event from the start, then wait for new ones until done.
        Yields PING when nothing happened for `ping_every` seconds (keeps proxies from
        closing an idle SSE connection during a long LLM call)."""
        i = 0
        while True:
            while i < len(self.events):
                yield self.events[i]
                i += 1
            if self.done:
                return
            self._new.clear()
            try:
                await asyncio.wait_for(self._new.wait(), timeout=ping_every)
            except asyncio.TimeoutError:
                yield PING


class ScanManager:
    def __init__(self) -> None:
        self.jobs: dict[str, ScanJob] = {}

    def get(self, scan_id: str) -> ScanJob | None:
        return self.jobs.get(scan_id)

    @property
    def running(self) -> int:
        return sum(1 for j in self.jobs.values() if not j.done)

    def sweep(self) -> int:
        """Drop finished jobs older than JOB_RETENTION_S. Returns how many were removed."""
        now = time.monotonic()
        stale = [k for k, j in self.jobs.items()
                 if j.done and j.finished_at is not None and now - j.finished_at > settings.job_retention_s]
        for k in stale:
            del self.jobs[k]
        return len(stale)

    def start(
        self, kind: str, value: str, depth: str,
        filename: str | None = None, language: str | None = None,
        content_hash: str | None = None,
    ) -> str:
        self.sweep()
        scan_id = uuid.uuid4().hex  # 122 random bits: results are only reachable by their id
        name = (filename or "snippet") if kind == "paste" else value
        job = ScanJob(scan_id, name[:80])
        self.jobs[scan_id] = job
        asyncio.create_task(self._run(job, kind, value, depth, filename, language, content_hash))
        return scan_id

    async def _run(
        self, job: ScanJob, kind: str, value: str, depth: str,
        filename: str | None, language: str | None, content_hash: str | None,
    ) -> None:
        res = await execute_scan(job.scan_id, job.name, kind, value, depth, filename, language,
                                 content_hash, push=job.push, save_fn=save)
        job.push({"stage": "result", "data": json.loads(res.model_dump_json())})
        job.finish(res)


def failed_result(scan_id: str, kind: str, name: str, message: str) -> ScanResult:
    return ScanResult(scan_id=scan_id, input=ScanInputMeta(kind=kind, name=name), status="error", error=message)


async def execute_scan(
    scan_id: str, name: str, kind: str, value: str, depth: str,
    filename: str | None, language: str | None, content_hash: str | None,
    *, push: Callable[[dict], None], save_fn: Callable[[ScanResult, str | None], None],
) -> ScanResult:
    """Run one scan end to end: build the workspace, audit with a hard timeout, persist.
    Shared by the in-process job manager and the Lambda worker. Never raises."""

    def fail(message: str) -> ScanResult:
        push({"stage": "error", "message": message})
        return failed_result(scan_id, kind, name, message)

    def progress(**kw) -> None:
        push(kw)

    try:
        # Workspace creation (esp. git clone) is blocking → run off the loop.
        workspace = await asyncio.to_thread(build_workspace, kind, value, filename, language)
    except Exception as e:  # noqa: BLE001
        res = fail(str(e))
    else:
        try:
            res = await asyncio.wait_for(
                run_scan(workspace, depth=depth, progress=progress, llm=get_llm(), scan_id=scan_id),
                timeout=settings.scan_timeout_s,
            )
        except asyncio.TimeoutError:
            workspace.dispose()
            res = fail(f"The audit took longer than {settings.scan_timeout_s}s and was stopped. "
                       "Try a smaller snippet.")
        except Exception:  # noqa: BLE001 - never leave a client hanging
            log.exception("scan %s crashed", scan_id)
            workspace.dispose()
            res = fail("The audit failed unexpectedly. Please try again.")

    try:
        save_fn(res, content_hash)
    except Exception:  # noqa: BLE001 - persistence failure shouldn't drop the result
        log.exception("could not save scan %s", scan_id)
    return res
