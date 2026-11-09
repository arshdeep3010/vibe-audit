"""Static analysis orchestration: LLM triage, then concurrent per-segment auditing."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Callable

from app.config import settings
from app.ingest.repomap import Repo, SourceFile, chunk_source
from app.llm.client import LLMClient
from app.llm.prompts import build_analysis_messages, build_triage_messages
from app.models.findings import Category, Finding, Severity, Source, Triage
from app.util import mask_secrets, number_lines

Progress = Callable[..., None]

_SEV = {s.value: s for s in Severity}
_CAT = {c.value: c for c in Category}


@dataclass
class AnalysisStats:
    units: int = 0
    failed: int = 0
    last_error: str = ""


async def run_static_analysis(
    repo: Repo,
    *,
    llm: LLMClient,
    progress: Progress,
    hotspots: set[str] | None = None,
    stats: AnalysisStats | None = None,
    skip_triage: bool = False,
) -> tuple[list[Finding], Triage]:
    """`skip_triage`: for a single pasted snippet, a separate triage call adds little; the
    audit call returns the code's profile (app type, frameworks) instead. Saves one LLM call."""
    stats = stats if stats is not None else AnalysisStats()
    triage = Triage() if skip_triage else await _triage(repo, llm, progress)
    want_profile = skip_triage

    targets = _select_targets(repo, triage, hotspots or set())
    units: list[tuple[SourceFile, int, int, str, bool]] = []
    for sf in targets:
        is_chunked = sf.lines > settings.chunk_lines
        for start, end, seg in chunk_source(sf):
            units.append((sf, start, end, seg, is_chunked))
        if len(units) >= settings.max_analysis_units:
            break
    units = units[: settings.max_analysis_units]

    progress(
        stage="analyze",
        message=f"Auditing {len(units)} segment(s) across {len(targets)} file(s)...",
        data={"units": len(units), "files": len(targets)},
    )

    sem = asyncio.Semaphore(settings.max_concurrency)
    tasks = [
        asyncio.create_task(_analyze_unit(llm, sf, start, end, seg, is_chunk, triage, sem, want_profile))
        for (sf, start, end, seg, is_chunk) in units
    ]

    findings: list[Finding] = []
    total = len(tasks) or 1
    done = 0
    for coro in asyncio.as_completed(tasks):
        try:
            res, truncated, profile = await coro
            findings.extend(res)
            if want_profile and profile and not triage.app_type:
                triage.app_type = str(profile.get("app_type") or "")[:120]
                triage.frameworks = _str_list(profile.get("frameworks"))[:8]
            if truncated:
                progress(stage="analyze", message=f"A reply was cut off by MAX_TOKENS; kept "
                         f"{len(res)} complete finding(s) from it.")
        except Exception as e:  # noqa: BLE001 - one bad segment shouldn't kill the scan
            stats.failed += 1
            stats.last_error = str(e)
            progress(stage="analyze", message=f"A segment failed: {e}")
        done += 1
        progress(
            stage="analyze",
            pct=int(done / total * 100),
            message=f"{done}/{total} segments analyzed - {len(findings)} findings so far",
        )

    stats.units = len(units)
    return findings, triage


async def _triage(repo: Repo, llm: LLMClient, progress: Progress) -> Triage:
    progress(stage="triage", message="Triaging the codebase...")
    try:
        msgs = build_triage_messages(repo.map_text(), repo.manifests_text() + _code_samples(repo))
        data = await llm.complete_json(msgs, max_tokens=1200, thinking=False)
        t = Triage(
            app_type=str(data.get("app_type", "") or ""),
            frameworks=_str_list(data.get("frameworks")),
            how_to_run=str(data.get("how_to_run", "") or ""),
            risk_areas=_str_list(data.get("risk_areas")),
            priority_files=_str_list(data.get("priority_files")),
            notes=str(data.get("notes", "") or ""),
        )
        progress(stage="triage", message=f"Looks like: {t.app_type or 'unknown app'}")
        return t
    except Exception as e:  # noqa: BLE001
        progress(stage="triage", message=f"Triage skipped ({e}); continuing.")
        return Triage()


def _code_samples(repo: Repo, max_files: int = 4, per_file: int = 3000, budget: int = 9000) -> str:
    """For small projects (e.g. a pasted snippet) the file map alone says almost nothing, so
    triage would just guess. Give it the head of each source file. Read as text only."""
    files = repo.analyzable()
    if not files or len(files) > max_files:
        return ""
    parts, used = [], 0
    for sf in files:
        block = f"--- {sf.rel} (first lines) ---\n{sf.text[:per_file]}"
        if used + len(block) > budget:
            break
        parts.append(block)
        used += len(block)
    return ("\n\nSource excerpts:\n" + "\n\n".join(parts)) if parts else ""


def _select_targets(repo: Repo, triage: Triage, hotspots: set[str]) -> list[SourceFile]:
    analyzable = repo.analyzable()
    pri = set(triage.priority_files or [])
    ordered = sorted(
        analyzable,
        key=lambda sf: sf.priority
        + (3.0 if sf.rel in pri else 0.0)
        + (4.0 if sf.rel in hotspots else 0.0),
        reverse=True,
    )
    return ordered[: settings.max_files]


async def _analyze_unit(
    llm: LLMClient,
    sf: SourceFile,
    start: int,
    end: int,
    seg: str,
    is_chunk: bool,
    triage: Triage,
    sem: asyncio.Semaphore,
    want_profile: bool = False,
) -> tuple[list[Finding], bool, dict | None]:
    numbered = number_lines(seg, start=start)
    msgs = build_analysis_messages(numbered, sf.rel, start, end, is_chunk, triage, want_profile)
    async with sem:
        data = await llm.complete_json(msgs, max_tokens=settings.max_tokens)
    truncated = isinstance(data, dict) and bool(data.get("_truncated"))
    profile = data.get("profile") if isinstance(data, dict) else None
    return _to_findings(data, sf), truncated, profile if isinstance(profile, dict) else None


def _to_findings(data, sf: SourceFile) -> list[Finding]:
    if isinstance(data, dict):
        items = data.get("findings") or []
    elif isinstance(data, list):
        items = data
    else:
        items = []

    out: list[Finding] = []
    for it in items[:12]:
        if not isinstance(it, dict):
            continue
        ls = _coerce_int(it.get("line_start"))
        le = _coerce_int(it.get("line_end")) or ls
        if ls and le and le < ls:
            ls, le = le, ls
        cwe = it.get("cwe")
        if not isinstance(cwe, str) or cwe.strip().lower() in ("", "null", "none", "n/a"):
            cwe = None
        out.append(
            Finding(
                title=mask_secrets(str(it.get("title") or "Untitled issue")[:200]),
                category=_CAT.get(str(it.get("category", "")).lower(), Category.logic),
                severity=_SEV.get(str(it.get("severity", "")).lower(), Severity.medium),
                file=sf.rel,
                line_start=ls,
                line_end=le,
                code_snippet=mask_secrets(_snippet(sf.text, ls, le)),
                description=mask_secrets(str(it.get("description") or "")),
                impact=mask_secrets(str(it.get("impact") or "")),
                recommendation=mask_secrets(str(it.get("recommendation") or "")),
                confidence=_coerce_conf(it.get("confidence")),
                source=Source.llm,
                cwe=cwe,
            )
        )
    return out


# --------------------------------------------------------------------------- #
# Coercion helpers (LLM output is untrusted — be defensive)
# --------------------------------------------------------------------------- #
def _str_list(v) -> list[str]:
    if isinstance(v, list):
        return [str(x) for x in v if x]
    if isinstance(v, str) and v.strip():
        return [v.strip()]
    return []


def _coerce_int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _coerce_conf(v) -> float:
    try:
        return min(max(float(v), 0.0), 1.0)
    except (TypeError, ValueError):
        return 0.6


def _snippet(text: str, ls: int | None, le: int | None, context: int = 1) -> str | None:
    if not ls:
        return None
    lines = text.splitlines()
    a = max(0, ls - 1 - context)
    b = min(len(lines), (le or ls) + context)
    seg = lines[a:b]
    return "\n".join(seg)[:1500] if seg else None
