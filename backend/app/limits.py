"""Input validation and abuse/cost controls for the scan API.

In public mode every new scan is an LLM bill, so the server (not the UI) enforces:
- snippet-only input, quick depth, and size caps;
- a per-client rolling-hour rate limit;
- a global per-UTC-day cap;
- a cap on scans running at the same time (checked by the caller).
Everything is in memory: correct for the single-process deployment this app is built for.
"""
from __future__ import annotations

import hashlib
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone

from app.config import Settings


class ScanRejected(Exception):
    """A scan request that must be refused, with the HTTP status and a user-facing message."""

    def __init__(self, status: int, message: str, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.retry_after = retry_after


@dataclass
class ScanInput:
    kind: str
    value: str
    depth: str
    filename: str | None
    language: str | None


def validate_input(req: ScanInput, s: Settings) -> ScanInput:
    """Normalise and check a scan request. Raises ScanRejected."""
    if req.kind not in ("local", "github", "paste"):
        raise ScanRejected(400, "kind must be local, github, or paste")
    if not req.value or not req.value.strip():
        raise ScanRejected(400, "Nothing to scan: the input is empty.")
    depth = req.depth if req.depth in ("quick", "deep") else "quick"

    if s.public:
        if req.kind != "paste":
            raise ScanRejected(403, "This hosted version only audits pasted snippets. "
                                    "Run VibeAudit locally to scan folders or repositories.")
        if depth == "deep":
            raise ScanRejected(403, "Deep scans run code in a sandbox and are only available locally.")

    if req.kind == "paste":
        size = len(req.value.encode("utf-8"))
        lines = req.value.count("\n") + 1
        if size > s.max_snippet_bytes:
            raise ScanRejected(413, f"Snippet is {size:,} bytes; the limit is {s.max_snippet_bytes:,}.")
        if lines > s.max_snippet_lines:
            raise ScanRejected(413, f"Snippet is {lines:,} lines; the limit is {s.max_snippet_lines:,}.")
        filename = (req.filename or "snippet.txt").strip()[:80] or "snippet.txt"
        return ScanInput("paste", req.value, depth, filename, req.language)

    return ScanInput(req.kind, req.value.strip(), depth, req.filename, req.language)


def content_hash(inp: ScanInput, model: str) -> str | None:
    """Cache key for a pasted snippet: same code, file name, depth and model → same report."""
    if inp.kind != "paste":
        return None
    h = hashlib.sha256()
    for part in (model, inp.depth, inp.filename or "", inp.value):
        h.update(part.encode("utf-8"))
        h.update(b"\0")
    return h.hexdigest()


class Limiter:
    """Per-client rolling-hour limit plus a global per-UTC-day cap."""

    def __init__(self, per_hour: int, per_day: int, clock=time.time) -> None:
        self.per_hour = per_hour
        self.per_day = per_day
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._day = ""
        self._day_count = 0
        self._lock = threading.Lock()

    def _today(self) -> str:
        return datetime.fromtimestamp(self._clock(), tz=timezone.utc).strftime("%Y-%m-%d")

    def remaining_today(self) -> int:
        with self._lock:
            if self._day != self._today():
                return self.per_day
            return max(0, self.per_day - self._day_count)

    def consume(self, client: str) -> None:
        """Record one new scan for `client`, or raise ScanRejected(429)."""
        now = self._clock()
        with self._lock:
            today = self._today()
            if today != self._day:
                self._day, self._day_count = today, 0
            if self._day_count >= self.per_day:
                tomorrow = (int(now) // 86400 + 1) * 86400
                raise ScanRejected(429, "The demo has reached today's scan limit. "
                                        "Try the sample, or come back tomorrow.",
                                   retry_after=max(60, tomorrow - int(now)))
            q = self._hits.setdefault(client, deque())
            while q and now - q[0] >= 3600:
                q.popleft()
            if len(q) >= self.per_hour:
                wait = int(3600 - (now - q[0])) + 1
                raise ScanRejected(429, f"You've run {self.per_hour} audits in the last hour. "
                                        f"Try again in about {max(1, wait // 60)} minute(s).",
                                   retry_after=wait)
            q.append(now)
            self._day_count += 1
            # keep the table small: drop clients with no recent hits
            if len(self._hits) > 5000:
                for k in [k for k, v in self._hits.items() if not v or now - v[-1] >= 3600]:
                    del self._hits[k]
