"""LLM verification pass — the main false-positive defense, and the judge for scanner hits.

Two kinds of finding are re-examined against the real code:
- high/critical findings from the LLM audit;
- every bandit and semgrep finding (up to MAX_JUDGED_SCANNER_FINDINGS, worst first). Scanners
  match patterns and over-report, so the model confirms or drops each one and, for the ones it
  keeps, writes the impact and the fix for this particular code.

Each gets a verdict (confirmed / plausible / dropped), a confidence and a one-line reason.
Dropped findings are removed during aggregation (dropped scanner hits are listed separately in
the report). Secret-scan hits are high-precision patterns and are trusted as-is.
"""
from __future__ import annotations

import asyncio
from typing import Callable

from app.config import settings
from app.ingest.repomap import Repo, SourceFile
from app.llm.client import LLMClient
from app.llm.prompts import build_verify_batch_messages, build_verify_messages
from app.models.findings import SEVERITY_ORDER, Finding, Severity, Source, Verdict
from app.util import mask_secrets, number_lines

Progress = Callable[..., None]

_VERDICT = {v.value: v for v in Verdict}
_VERIFY_SEVERITIES = {Severity.critical, Severity.high}
_JUDGED_SOURCES = {Source.semgrep, Source.bandit}
_WINDOW = 14  # lines of context on each side of the finding
_BATCH_MAX_LINES = 600


def _targets(findings: list[Finding], by_path: dict[str, SourceFile]) -> list[Finding]:
    llm = [f for f in findings
           if f.source == Source.llm and f.severity in _VERIFY_SEVERITIES and f.file in by_path]
    scanner = [f for f in findings if f.source in _JUDGED_SOURCES and f.file in by_path]
    scanner.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.confidence), reverse=True)
    return llm + scanner[: max(0, settings.max_judged_scanner_findings)]


async def verify_findings(
    findings: list[Finding], repo: Repo, *, llm: LLMClient, progress: Progress
) -> list[Finding]:
    by_path: dict[str, SourceFile] = {sf.rel: sf for sf in repo.files}
    targets = _targets(findings, by_path)
    if not targets:
        return findings

    n_scan = sum(1 for f in targets if f.source in _JUDGED_SOURCES)
    what = f"{len(targets) - n_scan} high-severity finding(s)"
    if n_scan:
        what += f" and judging {n_scan} scanner finding(s)"
    progress(stage="verify", message=f"Verifying {what}...")
    sem = asyncio.Semaphore(settings.max_concurrency)

    # Small files: check all of a file's findings in ONE call. Large files: per-finding windows.
    by_file: dict[str, list[Finding]] = {}
    for f in targets:
        by_file.setdefault(f.file, []).append(f)
    tasks = []
    for path, group in by_file.items():
        sf = by_path[path]
        if sf.lines <= _BATCH_MAX_LINES:
            tasks.append(asyncio.create_task(_verify_batch(llm, group, sf, sem)))
        else:
            tasks += [asyncio.create_task(_verify_single(llm, f, sf, sem)) for f in group]

    total = len(targets)
    done = dropped = 0
    for coro in asyncio.as_completed(tasks):
        try:
            verdicts = await coro
        except Exception as e:  # noqa: BLE001 - a failed verification just leaves findings as-is
            progress(stage="verify", message=f"A verification failed: {e}")
            continue
        done += len(verdicts)
        dropped += sum(1 for v in verdicts if v == Verdict.dropped)
        progress(stage="verify", pct=int(done / total * 100),
                 message=f"{done}/{total} verified - {dropped} dropped as false positive")

    return findings


def _text(v, limit: int = 600) -> str:
    return mask_secrets(" ".join(str(v).split()))[:limit] if isinstance(v, str) and v.strip() else ""


def _apply(f: Finding, data: dict) -> Verdict:
    f.verdict = _VERDICT.get(str(data.get("verdict", "")).lower(), Verdict.plausible)
    try:
        f.confidence = min(max(float(data["confidence"]), 0.0), 1.0)
    except (KeyError, TypeError, ValueError):
        pass
    f.judge_note = _text(data.get("reason"), 300)
    if f.source in _JUDGED_SOURCES:
        # The scanner's own text is generic; the model's is about this code.
        f.impact = _text(data.get("impact")) or f.impact
        f.recommendation = _text(data.get("fix") or data.get("recommendation")) or f.recommendation
    return f.verdict


async def _verify_batch(llm: LLMClient, group: list[Finding], sf: SourceFile, sem: asyncio.Semaphore) -> list[Verdict]:
    msgs = build_verify_batch_messages(group, sf.rel, number_lines(sf.text))
    per_item = sum(320 if f.source in _JUDGED_SOURCES else 160 for f in group)
    async with sem:
        data = await llm.complete_json(msgs, max_tokens=300 + per_item, thinking=False)
    items = data.get("verdicts") if isinstance(data, dict) else data
    out: list[Verdict] = []
    for it in items if isinstance(items, list) else []:
        if not isinstance(it, dict):
            continue
        try:
            idx = int(it.get("id")) - 1
        except (TypeError, ValueError):
            continue
        if 0 <= idx < len(group) and group[idx].verdict == Verdict.unverified:
            out.append(_apply(group[idx], it))
    return out


async def _verify_single(llm: LLMClient, f: Finding, sf: SourceFile, sem: asyncio.Semaphore) -> list[Verdict]:
    return [await _verify_one(llm, f, sf, sem)]


async def _verify_one(llm: LLMClient, f: Finding, sf: SourceFile, sem: asyncio.Semaphore) -> Verdict:
    lines = sf.text.splitlines()
    ls = (f.line_start or 1) - 1
    le = f.line_end or f.line_start or 1
    a = max(0, ls - _WINDOW)
    b = min(len(lines), le + _WINDOW)
    window = number_lines("\n".join(lines[a:b]), start=a + 1)

    msgs = build_verify_messages(f, window)
    async with sem:
        data = await llm.complete_json(msgs, max_tokens=700, thinking=False)

    if not isinstance(data, dict):
        return f.verdict
    return _apply(f, data)
