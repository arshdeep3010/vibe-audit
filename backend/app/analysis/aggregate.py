"""Merge, de-duplicate, rank findings and compute an overall risk grade."""
from __future__ import annotations

import re

from app.models.findings import (
    SEVERITY_ORDER,
    SEVERITY_WEIGHT,
    Category,
    Finding,
    Severity,
    Verdict,
)

_WORD_RE = re.compile(r"[a-z0-9]+")


def aggregate(findings: list[Finding]) -> dict:
    kept = [f for f in findings if f.verdict != Verdict.dropped]
    deduped = _dedupe(kept)
    deduped.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.confidence), reverse=True)
    score = _risk_score(deduped)
    return {
        "findings": deduped,
        "risk_score": score,
        "risk_grade": _grade(score),
        "counts": _counts(deduped),
        "dropped": len(kept) - len(deduped),
    }


def _norm_title(title: str) -> frozenset[str]:
    return frozenset(_WORD_RE.findall(title.lower()))


def _lines(f: Finding) -> tuple[int, int]:
    ls = f.line_start or 0
    le = f.line_end or ls
    return ls, le


def _overlap(a: Finding, b: Finding) -> bool:
    a0, a1 = _lines(a)
    b0, b1 = _lines(b)
    if not a0 or not b0:
        return False
    return not (a1 < b0 or b1 < a0)


def _similar(a: Finding, b: Finding) -> bool:
    if a.file != b.file or a.category != b.category:
        return False
    if _overlap(a, b):
        return True
    ta, tb = _norm_title(a.title), _norm_title(b.title)
    if not ta or not tb:
        return False
    jaccard = len(ta & tb) / len(ta | tb)
    return jaccard >= 0.6


def _dedupe(findings: list[Finding]) -> list[Finding]:
    kept: list[Finding] = []
    for f in findings:
        match = next((k for k in kept if _similar(k, f)), None)
        if match is None:
            kept.append(f)
            continue
        # Merge into the existing finding: keep worst severity + best confidence,
        # widen the line range, and keep whichever source list is richer.
        if SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[match.severity]:
            match.severity = f.severity
        match.confidence = max(match.confidence, f.confidence)
        fa, fb = _lines(f)
        ma, mb = _lines(match)
        if fa and ma:
            match.line_start = min(ma, fa)
            match.line_end = max(mb, fb)
        if not match.cwe and f.cwe:
            match.cwe = f.cwe
    return kept


def _risk_score(findings: list[Finding]) -> int:
    """0 = clean, 100 = very risky. Weighted by severity and confidence."""
    total = sum(SEVERITY_WEIGHT[f.severity] * f.confidence for f in findings)
    return int(min(100, round(total)))


def _grade(score: int) -> str:
    if score <= 5:
        return "A"
    if score <= 15:
        return "B"
    if score <= 30:
        return "C"
    if score <= 50:
        return "D"
    return "F"


def _counts(findings: list[Finding]) -> dict:
    by_sev = {s.value: 0 for s in Severity}
    by_cat = {c.value: 0 for c in Category}
    for f in findings:
        by_sev[f.severity.value] += 1
        by_cat[f.category.value] += 1
    return {"total": len(findings), "by_severity": by_sev, "by_category": by_cat}
