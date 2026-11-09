"""FastAPI app: REST + SSE API and the static single-page frontend."""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import uuid
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    StreamingResponse,
)
from pydantic import BaseModel

from app.config import PROJECT_ROOT, settings
from app.jobs import PING, ScanManager, failed_result
from app.limits import Limiter, ScanInput, ScanRejected, content_hash, validate_input
from app.llm.client import get_llm
from app.report import to_html, to_markdown

if settings.serverless:  # AWS Lambda: DynamoDB holds reports, limits and job progress
    from app import cloud as backend
    from app.cloud import DynamoLimiter as _Limiter
else:                    # one long-running process: SQLite + in-memory jobs and limits
    from app import store as backend
    _Limiter = Limiter

FRONTEND_DIR = PROJECT_ROOT / "frontend"
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("vibeaudit")

manager = ScanManager()
limiter = _Limiter(settings.rate_limit_per_hour, settings.daily_scan_cap)


async def _housekeeping() -> None:
    """Every few minutes: evict finished jobs from memory and delete expired results."""
    while True:
        await asyncio.sleep(300)
        try:
            manager.sweep()
            n = await asyncio.to_thread(backend.purge_expired)
            if n:
                log.info("purged %d expired result(s)", n)
        except Exception:  # noqa: BLE001
            log.exception("housekeeping failed")


@asynccontextmanager
async def lifespan(_: FastAPI):
    from app import store

    backend.init_db()
    n = backend.purge_expired()
    log.info("VibeAudit starting in %s mode (model %s, db %s, purged %d expired)",
             settings.app_mode, settings.model, store.DB_PATH.name, n)
    task = asyncio.create_task(_housekeeping())
    yield
    task.cancel()
    with suppress(asyncio.CancelledError):
        await task


app = FastAPI(title="VibeAudit", version="0.2.0", lifespan=lifespan, redoc_url=None)
_DOC_PATHS = ("/docs", "/docs/oauth2-redirect", "/openapi.json")

_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com; "  # Alpine needs eval
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)


@app.middleware("http")
async def guard_and_headers(request: Request, call_next):
    if settings.origin_secret and not hmac.compare_digest(
            request.headers.get("x-origin-verify", ""), settings.origin_secret):
        return JSONResponse({"detail": "Forbidden"}, status_code=403)  # not via CloudFront
    if settings.public and request.url.path in _DOC_PATHS:  # no API explorer on a hosted instance
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    if request.method in ("POST", "PUT", "PATCH"):
        length = request.headers.get("content-length")
        if length is None and settings.serverless:
            length = str(len(await request.body()))  # Lambda already holds the whole (<=6 MB) body
        if length is None:
            return JSONResponse({"detail": "Content-Length required."}, status_code=411)
        try:
            if int(length) > settings.max_request_bytes:
                return JSONResponse({"detail": "Request is too large."}, status_code=413)
        except ValueError:
            return JSONResponse({"detail": "Invalid Content-Length."}, status_code=400)
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Content-Security-Policy", _CSP)
    return response


def client_ip(request: Request) -> str:
    if settings.client_ip_header:  # e.g. CloudFront-Viewer-Address: "203.0.113.9:443", "2001:db8::1:443"
        value = request.headers.get(settings.client_ip_header, "").strip()
        if value:
            return value.rsplit(":", 1)[0] if ":" in value else value
    if settings.trust_proxy_headers:
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class ScanRequest(BaseModel):
    kind: str
    value: str
    depth: str = "quick"
    filename: str | None = None
    language: str | None = None


@app.get("/api/health")
def health() -> dict:
    if settings.serverless:
        backend.load_api_key()  # picks up a key set in SSM after deploy
    out = {
        "ok": True,
        "configured": settings.configured,
        "model": settings.model,
        "mode": settings.app_mode,
        "dynamic": settings.enable_dynamic and not settings.public,
        "progress": "poll" if settings.serverless else "sse",
        "limits": {
            "max_snippet_lines": settings.max_snippet_lines,
            "max_snippet_bytes": settings.max_snippet_bytes,
        },
    }
    if settings.public:
        out["limits"].update({
            "per_hour": settings.rate_limit_per_hour,
            "per_day": settings.daily_scan_cap,
            "remaining_today": limiter.remaining_today(),
        })
    return out


@app.post("/api/scan")
async def start_scan(req: ScanRequest, request: Request) -> JSONResponse:
    try:
        inp = validate_input(ScanInput(req.kind, req.value, req.depth, req.filename, req.language), settings)

        # Same snippet audited recently → hand back that report. Costs nothing, uses no quota.
        key = content_hash(inp, settings.model)
        cached = await asyncio.to_thread(backend.find_cached, key) if key else None
        if cached:
            return JSONResponse({"scan_id": cached, "cached": True})

        if settings.serverless:
            backend.load_api_key()
        if not get_llm().ready:
            raise ScanRejected(503, "The auditor isn't accepting audits right now. Please try again later."
                               if settings.serverless else
                               "No model API key configured: set NVIDIA_API_KEY (or LLM_API_KEY) in .env.")
        if settings.serverless:
            return await asyncio.to_thread(_start_serverless, inp, key, client_ip(request))
        if settings.public:
            if manager.running >= settings.max_running_scans:
                raise ScanRejected(429, "The auditor is busy with other scans. Try again in a minute.",
                                   retry_after=30)
            limiter.consume(client_ip(request))
    except ScanRejected as e:
        return _rejected(e)

    scan_id = manager.start(inp.kind, inp.value, inp.depth, inp.filename, inp.language, content_hash=key)
    log.info("scan %s started (%s, %s)", scan_id[:8], inp.kind, inp.depth)
    return JSONResponse({"scan_id": scan_id, "cached": False})


def _rejected(e: ScanRejected) -> JSONResponse:
    headers = {"Retry-After": str(e.retry_after)} if e.retry_after else None
    return JSONResponse({"detail": e.message}, status_code=e.status, headers=headers)


def _start_serverless(inp: ScanInput, key: str | None, ip: str) -> JSONResponse:
    """Lambda: take a running-scan slot, count the request, then hand the scan to the worker."""
    scan_id = uuid.uuid4().hex
    name = ((inp.filename or "snippet") if inp.kind == "paste" else inp.value)[:80]
    try:
        if settings.public:
            backend.acquire_slot(scan_id)
            try:
                limiter.consume(ip)
            except ScanRejected:
                backend.release_slot(scan_id)
                raise
    except ScanRejected as e:
        return _rejected(e)
    try:
        backend.create_job(scan_id, name)
        backend.invoke_worker({"scan_id": scan_id, "name": name, "kind": inp.kind, "value": inp.value,
                               "depth": inp.depth, "filename": inp.filename, "language": inp.language,
                               "content_hash": key})
    except Exception:  # noqa: BLE001
        log.exception("could not start worker for %s", scan_id[:8])
        backend.release_slot(scan_id)
        return JSONResponse({"detail": "Could not start the audit. Please try again."}, status_code=503)
    log.info("scan %s queued for the worker", scan_id[:8])
    return JSONResponse({"scan_id": scan_id, "cached": False})


@app.get("/api/scan/{scan_id}/progress")
def scan_progress(scan_id: str, after: int = Query(0, ge=0)) -> dict:
    """Polling alternative to the SSE stream (used on Lambda, where responses are buffered).
    Returns events after index `after`; a finished scan's last event is the full result."""
    if settings.serverless:
        got = backend.job_events(scan_id, after)
        if got is None:
            raise HTTPException(404, "unknown scan")
        events, done, age = got
        nxt = after + len(events)
        if done:
            res = backend.load(scan_id) or failed_result(scan_id, "paste", "snippet",
                                                         "The report could not be saved. Please try again.")
            events.append({"stage": "result", "data": json.loads(res.model_dump_json())})
        elif age > settings.scan_timeout_s + 180:  # the worker never started or was killed
            res = failed_result(scan_id, "paste", "snippet", "The audit did not finish. Please try again.")
            events += [{"stage": "error", "message": res.error},
                       {"stage": "result", "data": json.loads(res.model_dump_json())}]
            done = True
        return {"events": events, "next": nxt, "done": done}

    job = manager.get(scan_id)
    if job:
        events = job.events[after:]
        return {"events": events, "next": after + len(events), "done": job.done}
    res = backend.load(scan_id)
    if not res:
        raise HTTPException(404, "unknown scan")
    return {"events": [{"stage": "result", "data": json.loads(res.model_dump_json())}],
            "next": after, "done": True}


@app.get("/api/scan/{scan_id}/events")
async def scan_events(scan_id: str) -> StreamingResponse:
    job = manager.get(scan_id)
    if not job:
        raise HTTPException(404, "unknown scan")

    async def gen():
        async for ev in job.stream():
            yield ": ping\n\n" if ev is PING else f"data: {json.dumps(ev)}\n\n"

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _result_or_404(scan_id: str):
    job = manager.get(scan_id)
    if job and job.result:
        return job.result
    res = backend.load(scan_id)
    if not res:
        raise HTTPException(404, "unknown or expired scan")
    return res


@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: str) -> JSONResponse:
    res = _result_or_404(scan_id)
    return JSONResponse(json.loads(res.model_dump_json()))


@app.get("/api/scans")
def recent() -> dict:
    # A shared history would show every visitor's code to everyone else.
    if settings.public:
        raise HTTPException(404, "Not found")
    return {"scans": backend.list_recent()}


@app.get("/api/scan/{scan_id}/export")
def export(scan_id: str, format: str = "json"):
    res = _result_or_404(scan_id)
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in res.input.name)[:60]
    fname = f"vibeaudit-{safe}-{scan_id[:12]}"
    if format == "json":
        return PlainTextResponse(
            res.model_dump_json(indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{fname}.json"'},
        )
    if format == "md":
        return PlainTextResponse(
            to_markdown(res),
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="{fname}.md"'},
        )
    if format == "html":
        return HTMLResponse(to_html(res))
    raise HTTPException(400, "format must be json, md, or html")


@app.get("/")
@app.get("/how-it-works")  # same single-page app; it picks the view from the path
def index() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html", headers={"Cache-Control": "no-cache"})
