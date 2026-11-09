"""Async wrapper around the NVIDIA Integrate (OpenAI-compatible) chat API.

Features:
- streaming aggregation of both `content` and `reasoning_content` (thinking)
- retry with backoff on transient errors
- tolerant JSON extraction with a single repair attempt
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from typing import Any

from openai import (
    APIConnectionError,
    APIError,
    APIStatusError,
    APITimeoutError,
    AsyncOpenAI,
    InternalServerError,
    RateLimitError,
)

from app.config import settings


@dataclass
class LLMResponse:
    content: str
    reasoning: str


class LLMError(RuntimeError):
    pass


class LLMClient:
    def __init__(self) -> None:
        self._client: AsyncOpenAI | None = None
        if settings.configured:
            self._client = AsyncOpenAI(
                api_key=settings.nvidia_api_key,
                base_url=settings.nvidia_base_url,
                timeout=settings.request_timeout,
                max_retries=0,  # we handle retries ourselves
            )

    @property
    def ready(self) -> bool:
        return self._client is not None

    async def complete(
        self,
        messages: list[dict],
        *,
        temperature: float | None = None,
        top_p: float | None = None,
        max_tokens: int | None = None,
        thinking: bool | None = None,
    ) -> LLMResponse:
        if self._client is None:
            raise LLMError("NVIDIA_API_KEY is not set — add it to your .env file.")

        temperature = settings.analysis_temperature if temperature is None else temperature
        top_p = settings.analysis_top_p if top_p is None else top_p
        max_tokens = settings.max_tokens if max_tokens is None else max_tokens
        thinking = settings.enable_thinking if thinking is None else thinking
        extra_body = (
            {"chat_template_kwargs": {"enable_thinking": bool(thinking)}}
            if settings.send_thinking_flag else None
        )

        last_err: Exception | None = None
        for attempt in range(settings.max_retries + 1):
            try:
                stream = await self._client.chat.completions.create(
                    model=settings.model,
                    messages=messages,
                    temperature=temperature,
                    top_p=top_p,
                    max_tokens=max_tokens,
                    extra_body=extra_body,
                    stream=True,
                )
                content: list[str] = []
                reasoning: list[str] = []
                async for chunk in stream:
                    if not chunk.choices:
                        continue
                    delta = chunk.choices[0].delta
                    r = getattr(delta, "reasoning_content", None)
                    if r:
                        reasoning.append(r)
                    if getattr(delta, "content", None):
                        content.append(delta.content)
                return LLMResponse("".join(content), "".join(reasoning))
            except (APIConnectionError, APITimeoutError, RateLimitError, InternalServerError) as e:
                last_err = e
                await asyncio.sleep(min(2 ** attempt, 20))
            except APIStatusError as e:
                last_err = e
                if 500 <= e.status_code < 600:
                    await asyncio.sleep(min(2 ** attempt, 20))
                else:
                    msg = getattr(e, "message", str(e))
                    raise LLMError(f"LLM request failed ({e.status_code}): {msg}") from e
            except APIError as e:
                # Transient server-side errors (e.g. "Service temporarily overloaded")
                # surface as a base APIError during streaming — retry with backoff.
                last_err = e
                await asyncio.sleep(min(2 ** attempt, 20))

        raise LLMError(f"LLM request failed after {settings.max_retries + 1} attempts: {last_err}")

    async def complete_json(
        self,
        messages: list[dict],
        *,
        temperature: float | None = None,
        top_p: float | None = None,
        max_tokens: int | None = None,
        thinking: bool | None = None,
    ) -> Any:
        """Call the model and parse a JSON object/array from its reply."""
        resp = await self.complete(
            messages, temperature=temperature, top_p=top_p, max_tokens=max_tokens, thinking=thinking
        )
        data = _extract_json(resp.content.strip() or resp.reasoning.strip())
        if data is not None:
            return data
        # The reply was most likely cut off by the token budget (thinking shares it with the
        # answer). Keep every complete finding object that made it through.
        salvaged = _salvage_findings(resp.content)
        if salvaged:
            return {"findings": salvaged, "_truncated": True}

        # Retry from scratch with thinking off: the answer then gets the whole token budget.
        # (Feeding back a truncated reply as a "repair" just reproduces the truncation.)
        resp2 = await self.complete(
            messages, temperature=0.0, top_p=top_p, max_tokens=max_tokens, thinking=False
        )
        data = _extract_json(resp2.content.strip())
        if data is not None:
            return data
        salvaged = _salvage_findings(resp2.content)
        if salvaged:
            return {"findings": salvaged, "_truncated": True}
        raise LLMError(
            "Could not parse JSON from the model response "
            f"(reply was {len(resp2.content)} chars; it may have been cut off by MAX_TOKENS)."
        )


# --------------------------------------------------------------------------- #
# Tolerant JSON extraction
# --------------------------------------------------------------------------- #
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def _candidates(text: str):
    yield text
    m = _FENCE_RE.search(text)
    if m:
        yield m.group(1).strip()
    i, j = text.find("{"), text.rfind("}")
    if i != -1 and j > i:
        yield text[i : j + 1]
    i, j = text.find("["), text.rfind("]")
    if i != -1 and j > i:
        yield text[i : j + 1]


def _extract_json(text: str) -> Any | None:
    if not text:
        return None
    for cand in _candidates(text):
        try:
            return json.loads(cand)
        except (json.JSONDecodeError, ValueError):
            continue
    return None


def _salvage_findings(text: str) -> list[dict]:
    """Recover the complete objects from a truncated `{"findings":[{...},{...},{..` reply."""
    if not text:
        return []
    k = text.find('"findings"')
    if k == -1:
        return []
    i = text.find("[", k)
    if i == -1:
        return []
    dec = json.JSONDecoder()
    out: list[dict] = []
    pos = i + 1
    while pos < len(text):
        while pos < len(text) and text[pos] in " \t\r\n,":
            pos += 1
        if pos >= len(text) or text[pos] != "{":
            break
        try:
            obj, pos = dec.raw_decode(text, pos)
        except json.JSONDecodeError:
            break  # reached the cut-off object
        if isinstance(obj, dict):
            out.append(obj)
    return out


_singleton: LLMClient | None = None


def get_llm() -> LLMClient:
    global _singleton
    if _singleton is None:
        _singleton = LLMClient()
    return _singleton
