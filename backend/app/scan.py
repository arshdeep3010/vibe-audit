"""End-to-end scan orchestration used by both the CLI and the web API."""
from __future__ import annotations

import asyncio
import time
from typing import Callable

from app.analysis.aggregate import aggregate
from app.analysis.deterministic import run_deterministic
from app.analysis.dynamic import run_dynamic
from app.analysis.static import AnalysisStats, run_static_analysis
from app.analysis.verify import verify_findings
from app.config import settings
from app.ingest.repomap import build_repo
from app.ingest.sources import Workspace
from app.llm.client import LLMClient, get_llm
from app.models.findings import Finding, ScanResult

Progress = Callable[..., None]


def _noop(**kwargs) -> None:
    pass


async def run_scan(
    workspace: Workspace,
    *,
    depth: str = "quick",
    progress: Progress | None = None,
    llm: LLMClient | None = None,
    scan_id: str | None = None,
) -> ScanResult:
    progress = progress or _noop
    llm = llm or get_llm()

    result = ScanResult(input=workspace.meta, depth=depth, status="running")
    if scan_id:
        result.scan_id = scan_id
    t0 = time.perf_counter()

    def log(stage: str, message: str = "", **kw) -> None:
        if message:
            result.log.append(f"[{stage}] {message}")
        progress(scan_id=result.scan_id, stage=stage, message=message, **kw)

    try:
        if not llm.ready:
            raise RuntimeError("NVIDIA_API_KEY is not configured. Add it to your .env file.")

        log("map", f"Scanning {workspace.meta.name} ...")
        repo = await asyncio.to_thread(build_repo, workspace.root)
        result.repo_map = repo.to_map()
        log(
            "map",
            f"Found {result.repo_map.total_files} files "
            f"({len(repo.analyzable())} analyzable).",
            data={"total_files": result.repo_map.total_files},
        )
        if not repo.analyzable():
            result.status = "done"
            result.risk_grade = "?"
            log("done", "No analyzable source files were found.")
            result.timings["total_s"] = round(time.perf_counter() - t0, 1)
            return result

        # Phase 3 — deterministic pre-pass (secret scan + bandit/semgrep when installed).
        # Runs off-loop; it uses subprocesses and must not touch the progress queue from a thread.
        det_findings: list[Finding] = []
        hotspots: set[str] = set()
        if settings.enable_deterministic:
            t_det = time.perf_counter()
            log("deterministic", "Running deterministic scanners (secrets, bandit, semgrep)...")
            det_findings, hotspots = await asyncio.to_thread(run_deterministic, repo)
            result.timings["deterministic_s"] = round(time.perf_counter() - t_det, 1)
            log("deterministic",
                f"{len(det_findings)} deterministic finding(s) across {len(hotspots)} hotspot file(s).")

        t_static = time.perf_counter()
        astats = AnalysisStats()
        llm_findings, triage = await run_static_analysis(
            repo, llm=llm, progress=progress, hotspots=hotspots, stats=astats,
            skip_triage=workspace.meta.kind == "paste",
        )
        result.triage = triage
        result.timings["static_s"] = round(time.perf_counter() - t_static, 1)
        if astats.units and astats.failed == astats.units:
            # Nothing was actually audited — reporting a clean grade here would be a lie.
            raise RuntimeError(
                f"The LLM audit failed for all {astats.units} code segment(s), so nothing was "
                f"checked. Last error: {astats.last_error}"
            )
        if astats.failed:
            log("analyze", f"WARNING: {astats.failed}/{astats.units} segment(s) could not be "
                f"audited ({astats.last_error}). Results are incomplete.")

        findings = llm_findings + det_findings

        # Phase 3 — LLM verification pass (false-positive filtering on high/critical LLM findings).
        if settings.enable_verification:
            t_verify = time.perf_counter()
            findings = await verify_findings(findings, repo, llm=llm, progress=progress)
            result.timings["verify_s"] = round(time.perf_counter() - t_verify, 1)

        # Phase 4 — dynamic analysis (deep scans only). Runs the app in a Docker sandbox and
        # captures build/boot/runtime errors. Blocking (subprocess + optional sync browser), so
        # it runs off-loop and returns its own log lines rather than touching the progress queue.
        if depth == "deep" and settings.enable_dynamic:
            log("dynamic", f"Running dynamic analysis in a Docker sandbox (up to {settings.dynamic_timeout_s}s)...")
            t_dyn = time.perf_counter()
            dyn = await asyncio.to_thread(run_dynamic, repo, result.scan_id)
            for line in dyn.logs:
                log("dynamic", line)
            findings = findings + dyn.findings
            result.timings["dynamic_s"] = round(time.perf_counter() - t_dyn, 1)
            log("dynamic", f"Dynamic analysis contributed {len(dyn.findings)} finding(s).")

        log("aggregate", "Ranking and de-duplicating findings...")
        agg = aggregate(findings)
        result.findings = agg["findings"]
        result.risk_score = agg["risk_score"]
        result.risk_grade = agg["risk_grade"]
        result.counts = agg["counts"]
        if agg.get("dropped"):
            result.counts["dropped_false_positives"] = agg["dropped"]
        if astats.failed:
            result.counts["failed_segments"] = astats.failed
            result.counts["total_segments"] = astats.units

        result.status = "done"
        result.timings["total_s"] = round(time.perf_counter() - t0, 1)
        log(
            "done",
            f"Grade {result.risk_grade} - {result.counts['total']} findings "
            f"in {result.timings['total_s']}s.",
            data={"risk_grade": result.risk_grade, "counts": result.counts},
        )
    except Exception as e:  # noqa: BLE001
        result.status = "error"
        result.error = str(e)
        result.timings["total_s"] = round(time.perf_counter() - t0, 1)
        log("error", str(e))
    finally:
        workspace.dispose()

    return result
