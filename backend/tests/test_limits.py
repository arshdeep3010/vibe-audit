"""Input validation, cache keys and the rate limiter."""
from __future__ import annotations

import pytest

from app.config import settings
from app.limits import Limiter, ScanInput, ScanRejected, content_hash, validate_input


def inp(kind="paste", value="print(1)", depth="quick", filename="a.py"):
    return ScanInput(kind, value, depth, filename, None)


@pytest.mark.parametrize("kind", ["local", "github"])
def test_public_mode_only_accepts_snippets(mode, kind):
    mode("public")
    with pytest.raises(ScanRejected) as e:
        validate_input(inp(kind=kind, value="C:\\somewhere"), settings)
    assert e.value.status == 403


def test_public_mode_refuses_deep(mode):
    mode("public")
    with pytest.raises(ScanRejected) as e:
        validate_input(inp(depth="deep"), settings)
    assert e.value.status == 403


def test_local_mode_allows_folders_and_deep(mode):
    mode("local")
    out = validate_input(inp(kind="local", value="  C:\\app  ", depth="deep"), settings)
    assert out.kind == "local" and out.depth == "deep" and out.value == "C:\\app"


def test_empty_and_unknown_inputs_are_rejected(mode):
    mode("public")
    with pytest.raises(ScanRejected) as e:
        validate_input(inp(value="   "), settings)
    assert e.value.status == 400
    with pytest.raises(ScanRejected):
        validate_input(inp(kind="ftp"), settings)


def test_snippet_size_caps(mode):
    mode("public")
    too_many_lines = "\n".join(["x"] * (settings.max_snippet_lines + 1))
    with pytest.raises(ScanRejected) as e:
        validate_input(inp(value=too_many_lines), settings)
    assert e.value.status == 413 and "lines" in e.value.message

    too_big = "x" * (settings.max_snippet_bytes + 1)
    with pytest.raises(ScanRejected) as e:
        validate_input(inp(value=too_big), settings)
    assert e.value.status == 413 and "bytes" in e.value.message

    ok = "\n".join(["x"] * settings.max_snippet_lines)
    assert validate_input(inp(value=ok), settings).kind == "paste"


def test_unknown_depth_falls_back_to_quick(mode):
    mode("local")
    assert validate_input(inp(depth="turbo"), settings).depth == "quick"


def test_content_hash_is_stable_and_specific():
    a = content_hash(inp(), "m1")
    assert a == content_hash(inp(), "m1")
    assert a != content_hash(inp(filename="b.py"), "m1")
    assert a != content_hash(inp(value="print(2)"), "m1")
    assert a != content_hash(inp(), "m2")
    assert content_hash(inp(kind="local", value="C:\\x"), "m1") is None


class Clock:
    def __init__(self, t: float = 1_700_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def test_rate_limit_per_client_per_hour():
    clock = Clock()
    lim = Limiter(per_hour=3, per_day=100, clock=clock)
    for _ in range(3):
        lim.consume("1.1.1.1")
    with pytest.raises(ScanRejected) as e:
        lim.consume("1.1.1.1")
    assert e.value.status == 429 and e.value.retry_after
    lim.consume("2.2.2.2")            # other clients are unaffected
    clock.t += 3601                   # the window rolls
    lim.consume("1.1.1.1")


def test_daily_cap_is_global_and_resets_next_utc_day():
    clock = Clock(1_700_000_000.0)    # 2023-11-14 22:13 UTC
    lim = Limiter(per_hour=100, per_day=2, clock=clock)
    lim.consume("a")
    lim.consume("b")
    assert lim.remaining_today() == 0
    with pytest.raises(ScanRejected) as e:
        lim.consume("c")
    assert "today" in e.value.message
    clock.t += 2 * 3600               # past midnight UTC
    assert lim.remaining_today() == 2
    lim.consume("c")
