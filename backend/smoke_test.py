"""Phase 0 smoke test: confirm the NVIDIA LLM connection, streaming, and JSON parsing.

Run from the backend/ directory:
    python smoke_test.py
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from app.config import settings  # noqa: E402
from app.llm.client import get_llm  # noqa: E402


async def main() -> int:
    print(f"model      : {settings.model}")
    print(f"base_url   : {settings.nvidia_base_url}")
    print(f"configured : {settings.configured}")
    if not settings.configured:
        print("\nNo API key found. Put NVIDIA_API_KEY in the project-root .env file.")
        return 1

    llm = get_llm()

    print("\n[1/2] plain streaming call...")
    resp = await llm.complete(
        [{"role": "user", "content": "Say 'VibeAudit online' and nothing else."}],
        thinking=False,
        max_tokens=50,
    )
    print(f"  content  : {resp.content.strip()!r}")
    print(f"  reasoning: {len(resp.reasoning)} chars")

    print("\n[2/2] JSON parsing call...")
    data = await llm.complete_json(
        [{"role": "user", "content":
          'Return ONLY this JSON with ok=true and a one-word status: '
          '{"ok": true, "status": "..."}'}],
        thinking=False,
        max_tokens=100,
    )
    print(f"  parsed   : {data}")

    ok = isinstance(data, dict) and data.get("ok") is True
    print("\nSMOKE TEST PASSED" if ok else "\nSMOKE TEST: unexpected JSON shape")
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
