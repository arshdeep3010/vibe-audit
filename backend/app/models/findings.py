"""Pydantic data models for findings and scan results."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class Severity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Category(str, enum.Enum):
    security = "security"
    logic = "logic"
    quality = "quality"


class Source(str, enum.Enum):
    llm = "llm"
    secret_scan = "secret-scan"
    semgrep = "semgrep"
    bandit = "bandit"
    eslint = "eslint"
    dynamic = "dynamic"


class Verdict(str, enum.Enum):
    confirmed = "confirmed"
    plausible = "plausible"
    dropped = "dropped"
    unverified = "unverified"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.critical: 4,
    Severity.high: 3,
    Severity.medium: 2,
    Severity.low: 1,
    Severity.info: 0,
}

# Points subtracted from a 100-point health budget (scaled by confidence).
SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.critical: 25.0,
    Severity.high: 12.0,
    Severity.medium: 5.0,
    Severity.low: 2.0,
    Severity.info: 0.5,
}


def _uuid() -> str:
    return uuid.uuid4().hex[:12]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #
class Finding(BaseModel):
    id: str = Field(default_factory=_uuid)
    title: str
    category: Category
    severity: Severity
    file: str
    line_start: int | None = None
    line_end: int | None = None
    code_snippet: str | None = None
    description: str = ""
    impact: str = ""
    recommendation: str = ""
    confidence: float = 0.6
    source: Source = Source.llm
    cwe: str | None = None
    verdict: Verdict = Verdict.unverified

    @property
    def rank(self) -> float:
        return SEVERITY_ORDER[self.severity] * 10 + self.confidence * 5


class RepoFileInfo(BaseModel):
    path: str
    language: str
    bytes: int
    lines: int
    is_manifest: bool = False


class RepoMap(BaseModel):
    root_name: str
    files: list[RepoFileInfo] = Field(default_factory=list)
    total_bytes: int = 0
    total_files: int = 0
    truncated: bool = False
    languages: dict[str, int] = Field(default_factory=dict)


class ScanInputMeta(BaseModel):
    kind: str  # local | github | paste
    name: str
    detail: str | None = None
    commit: str | None = None


class Triage(BaseModel):
    app_type: str = ""
    frameworks: list[str] = Field(default_factory=list)
    how_to_run: str = ""
    risk_areas: list[str] = Field(default_factory=list)
    priority_files: list[str] = Field(default_factory=list)
    notes: str = ""


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=_uuid)
    created_at: str = Field(default_factory=_now)
    status: str = "pending"  # pending | running | done | error
    depth: str = "quick"     # quick | deep
    input: ScanInputMeta
    repo_map: RepoMap | None = None
    triage: Triage | None = None
    findings: list[Finding] = Field(default_factory=list)
    risk_score: int = 0      # 0 (safe) .. 100 (very risky)
    risk_grade: str = "?"    # A..F
    counts: dict = Field(default_factory=dict)
    timings: dict = Field(default_factory=dict)
    log: list[str] = Field(default_factory=list)
    error: str | None = None


class ProgressEvent(BaseModel):
    scan_id: str
    stage: str  # ingest|map|triage|analyze|verify|aggregate|dynamic|done|error|log
    message: str = ""
    pct: int | None = None
    data: dict | None = None
    at: str = Field(default_factory=_now)
