"""Command-line scanner (useful for testing the engine before the web UI).

Run from the backend/ directory:
    python scan_cli.py --path ../fixtures/buggy-sample
    python scan_cli.py --github https://github.com/user/repo
    python scan_cli.py --paste-file some_file.py --out report.json
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # make `app` importable
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from app.ingest import sources  # noqa: E402
from app.models.findings import Severity  # noqa: E402
from app.scan import run_scan  # noqa: E402
from app.store import init_db, save  # noqa: E402

_SEV_TAG = {
    Severity.critical: "CRIT",
    Severity.high: "HIGH",
    Severity.medium: "MED ",
    Severity.low: "LOW ",
    Severity.info: "INFO",
}


def _progress(**kw) -> None:
    stage = kw.get("stage", "")
    msg = kw.get("message", "")
    pct = kw.get("pct")
    prefix = f"[{stage}]".ljust(12)
    tail = f" ({pct}%)" if pct is not None else ""
    if msg or tail:
        print(f"{prefix} {msg}{tail}", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="VibeAudit — find bugs in AI-coded apps.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--path", help="local project directory")
    src.add_argument("--github", help="public GitHub repo URL")
    src.add_argument("--paste-file", help="single file to analyze as a snippet")
    ap.add_argument("--depth", choices=["quick", "deep"], default="quick")
    ap.add_argument("--out", help="write full JSON result to this path")
    args = ap.parse_args()

    if args.path:
        ws = sources.from_local(args.path)
    elif args.github:
        ws = sources.from_github(args.github)
    else:
        p = Path(args.paste_file)
        ws = sources.from_paste(p.read_text(encoding="utf-8", errors="replace"), filename=p.name)

    init_db()
    result = asyncio.run(run_scan(ws, depth=args.depth, progress=_progress))
    save(result)

    print("\n" + "=" * 70)
    print(f"  {result.input.name}  —  grade {result.risk_grade}  "
          f"(risk {result.risk_score}/100)  —  {result.status}")
    print("=" * 70)
    if result.error:
        print(f"ERROR: {result.error}")
        return 1

    for f in result.findings:
        loc = f":{f.line_start}" if f.line_start else ""
        print(f"\n[{_SEV_TAG[f.severity]}] {f.category.value:8} {f.file}{loc}  (conf {f.confidence:.0%})")
        print(f"   {f.title}")
        if f.impact:
            print(f"   impact: {f.impact}")
        if f.recommendation:
            print(f"   fix:    {f.recommendation}")

    c = result.counts or {}
    print(f"\n{c.get('total', 0)} findings  "
          f"{c.get('by_severity', {})}  scan_id={result.scan_id}")

    if args.out:
        Path(args.out).write_text(result.model_dump_json(indent=2), encoding="utf-8")
        print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
