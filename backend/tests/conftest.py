"""Shared fixtures. No test calls a real model: a FakeLLM answers with canned JSON."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # make `app` importable

from app.config import settings  # noqa: E402

SNIPPET = (Path(__file__).resolve().parents[2] / "fixtures" / "snippets" / "express-api.js").read_text(encoding="utf-8")


class FakeLLM:
    """Stands in for LLMClient. Records every call; `fail=True` makes audit calls raise."""

    ready = True

    def __init__(self, fail: bool = False) -> None:
        self.calls: list[str] = []
        self.fail = fail

    async def complete_json(self, messages, **_):
        system = messages[0]["content"]
        if "verify" in system.lower() and "verdicts" in system:
            self.calls.append("verify_batch")
            return {"verdicts": [
                {"id": 1, "verdict": "confirmed", "confidence": 0.95},
                {"id": 2, "verdict": "dropped", "confidence": 0.2},
            ]}
        if "TRUE POSITIVE" in system:
            self.calls.append("verify_one")
            return {"verdict": "confirmed", "confidence": 0.9}
        if "triaging" in system:
            self.calls.append("triage")
            return {"app_type": "Express API", "frameworks": ["Express"]}
        self.calls.append("analyze")
        if self.fail:
            raise RuntimeError("model unavailable")
        return {
            "findings": [
                {"category": "security", "title": "SQL injection in /login", "severity": "critical",
                 "line_start": 22, "line_end": 22, "description": "String-built SQL.",
                 "impact": "Auth bypass.", "recommendation": "Use placeholders.", "confidence": 0.9, "cwe": "CWE-89"},
                {"category": "logic", "title": "Speculative issue", "severity": "high",
                 "line_start": 5, "line_end": 5, "description": "Probably fine.",
                 "impact": "-", "recommendation": "-", "confidence": 0.5, "cwe": None},
                {"category": "quality", "title": "Unhandled db errors", "severity": "medium",
                 "line_start": 23, "line_end": 23, "description": "err ignored.",
                 "impact": "Crash.", "recommendation": "Check err.", "confidence": 0.8, "cwe": None},
            ],
            "profile": {"app_type": "Express API", "frameworks": ["Express", "mysql"]},
        }


@pytest.fixture
def tmp_store(tmp_path, monkeypatch):
    """Point SQLite at a throwaway file."""
    from app import store

    monkeypatch.setattr(store, "DB_PATH", tmp_path / "test.db")
    store.init_db()
    return store


@pytest.fixture
def mode(monkeypatch):
    """mode('public') / mode('local') switches APP_MODE for one test."""
    def _set(value: str) -> None:
        monkeypatch.setattr(settings, "app_mode", value)
    return _set
