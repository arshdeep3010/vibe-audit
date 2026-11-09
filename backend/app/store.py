"""Persist scan results in SQLite (full JSON blob + queryable summary columns).

Pasted code itself is never stored: only the report (findings with short, secret-masked
snippets). In public mode rows expire after RESULT_TTL_HOURS.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.config import settings
from app.models.findings import ScanResult

# Separate files per mode: public-mode expiry must never delete your local history.
DB_PATH: Path = settings.data_dir / ("vibeaudit-public.db" if settings.public else "vibeaudit.db")


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _iso_hours_ago(hours: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


def init_db() -> None:
    with _conn() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                scan_id     TEXT PRIMARY KEY,
                created_at  TEXT,
                status      TEXT,
                name        TEXT,
                kind        TEXT,
                risk_grade  TEXT,
                risk_score  INTEGER,
                total       INTEGER,
                json        TEXT
            )
            """
        )
        cols = {r["name"] for r in c.execute("PRAGMA table_info(scans)")}
        if "content_hash" not in cols:  # migration for databases created before caching
            c.execute("ALTER TABLE scans ADD COLUMN content_hash TEXT")
        c.execute("CREATE INDEX IF NOT EXISTS ix_scans_hash ON scans(content_hash)")
        c.execute("CREATE INDEX IF NOT EXISTS ix_scans_created ON scans(created_at)")


def _cacheable(result: ScanResult) -> bool:
    return result.status == "done" and not (result.counts or {}).get("failed_segments")


def save(result: ScanResult, content_hash: str | None = None) -> None:
    key = content_hash if content_hash and _cacheable(result) else None
    with _conn() as c:
        c.execute(
            """
            INSERT INTO scans (scan_id, created_at, status, name, kind,
                               risk_grade, risk_score, total, json, content_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                status=excluded.status, risk_grade=excluded.risk_grade,
                risk_score=excluded.risk_score, total=excluded.total,
                json=excluded.json, content_hash=excluded.content_hash
            """,
            (
                result.scan_id,
                result.created_at,
                result.status,
                result.input.name,
                result.input.kind,
                result.risk_grade,
                result.risk_score,
                (result.counts or {}).get("total", 0),
                result.model_dump_json(),
                key,
            ),
        )


def _expired_clause() -> tuple[str, tuple]:
    if settings.public and settings.result_ttl_hours > 0:
        return " AND created_at >= ?", (_iso_hours_ago(settings.result_ttl_hours),)
    return "", ()


def load(scan_id: str) -> ScanResult | None:
    clause, args = _expired_clause()
    with _conn() as c:
        row = c.execute(f"SELECT json FROM scans WHERE scan_id = ?{clause}", (scan_id, *args)).fetchone()
    if not row:
        return None
    return ScanResult.model_validate_json(row["json"])


def find_cached(content_hash: str) -> str | None:
    """scan_id of a recent, complete report for exactly this input, if any."""
    if not content_hash or settings.cache_ttl_hours <= 0:
        return None
    with _conn() as c:
        row = c.execute(
            "SELECT scan_id FROM scans WHERE content_hash = ? AND status = 'done' "
            "AND created_at >= ? ORDER BY created_at DESC LIMIT 1",
            (content_hash, _iso_hours_ago(settings.cache_ttl_hours)),
        ).fetchone()
    return row["scan_id"] if row else None


def purge_expired() -> int:
    """Delete results past RESULT_TTL_HOURS (public mode only). Returns rows deleted."""
    if not settings.public or settings.result_ttl_hours <= 0:
        return 0
    with _conn() as c:
        cur = c.execute("DELETE FROM scans WHERE created_at < ?", (_iso_hours_ago(settings.result_ttl_hours),))
        return cur.rowcount


def list_recent(limit: int = 25) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            """
            SELECT scan_id, created_at, status, name, kind, risk_grade, risk_score, total
            FROM scans ORDER BY created_at DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]
