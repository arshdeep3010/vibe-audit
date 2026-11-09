"""LLM-output parsing and secret masking."""
from __future__ import annotations

from app.llm.client import _extract_json, _salvage_findings
from app.util import mask_secrets


def test_extract_json_handles_fences_and_prose():
    assert _extract_json('```json\n{"findings": []}\n```') == {"findings": []}
    assert _extract_json('Sure! {"a": 1} hope that helps') == {"a": 1}
    assert _extract_json("no json here") is None


def test_salvage_keeps_complete_findings_from_a_cut_off_reply():
    cut = '{"findings":[{"title":"a","x":[1,2]}, {"title":"b"},{"title":"c","desc":"cut of'
    assert _extract_json(cut) is None
    assert _salvage_findings(cut) == [{"title": "a", "x": [1, 2]}, {"title": "b"}]


def test_salvage_returns_nothing_when_nothing_is_recoverable():
    assert _salvage_findings('{"findings":[]}') == []
    assert _salvage_findings('{"findings":[{"title":"half') == []
    assert _salvage_findings("") == []


def test_mask_hides_common_key_formats():
    for secret in ("sk_live_FAKE_EXAMPLE_KEY_0000", "sk-proj-abcdefghijklmnop1234",
                   "nvapi-abcdefghijklmnopqrstuvwxyz", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"):
        masked = mask_secrets(f'key = "{secret}"')
        assert secret not in masked and "***" in masked
