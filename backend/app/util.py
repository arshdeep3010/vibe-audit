"""Small shared helpers: line numbering, secret masking, text utilities."""
from __future__ import annotations

import re

# ---- Line numbering (so the LLM can cite exact line numbers) ----

def number_lines(text: str, start: int = 1) -> str:
    """Prefix every line with '<n>| ' starting at `start`."""
    return "\n".join(f"{i}| {line}" for i, line in enumerate(text.splitlines(), start=start))


# ---- Secret masking (never surface raw secrets in reports/UI) ----

_SECRET_PATTERNS = [
    re.compile(r"nvapi-[A-Za-z0-9_\-]{10,}"),
    re.compile(r"sk[-_][A-Za-z0-9][A-Za-z0-9_\-]{14,}"),   # sk-..., sk_live_..., sk_test_...
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{12,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    # JWT
    re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
]


def mask_secret_value(s: str) -> str:
    if len(s) <= 8:
        return "***"
    return s[:4] + "***" + s[-4:]


def mask_secrets(text: str | None) -> str | None:
    """Redact anything that looks like a credential."""
    if not text:
        return text
    for pat in _SECRET_PATTERNS:
        text = pat.sub(lambda m: mask_secret_value(m.group(0)), text)
    return text


# ---- Misc ----

def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated {len(text) - limit} chars]"


def human_bytes(n: int) -> str:
    f = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if f < 1024 or unit == "GB":
            return f"{int(f)}{unit}" if unit == "B" else f"{f:.1f}{unit}"
        f /= 1024
    return f"{f:.1f}GB"


def looks_binary(data: bytes) -> bool:
    """Heuristic: a NUL byte in the first 4KB means it's not source text."""
    return b"\x00" in data[:4096]
