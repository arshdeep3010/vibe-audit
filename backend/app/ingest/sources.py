"""Turn any input (local dir, GitHub URL, pasted snippet) into a Workspace on disk.

All ingested code is treated as UNTRUSTED. We only ever read it as text here; nothing is
imported or executed. GitHub clones are shallow and non-interactive.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from app.models.findings import ScanInputMeta

_GIT_HOST_RE = re.compile(r"(github\.com|gitlab\.com|bitbucket\.org)", re.IGNORECASE)

_EXT_BY_HINT = {
    "javascript": ".js",
    "typescript": ".ts",
    "python": ".py",
    "jsx": ".jsx",
    "tsx": ".tsx",
    "html": ".html",
    "go": ".go",
    "java": ".java",
    "php": ".php",
    "ruby": ".rb",
}


@dataclass
class Workspace:
    root: Path
    meta: ScanInputMeta
    cleanup: bool = False  # True for temp dirs we created

    def dispose(self) -> None:
        if self.cleanup and self.root.exists():
            shutil.rmtree(self.root, ignore_errors=True)


def from_local(path: str) -> Workspace:
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise ValueError(f"Path does not exist: {p}")
    if not p.is_dir():
        raise ValueError(f"Not a directory: {p}")
    meta = ScanInputMeta(kind="local", name=p.name, detail=str(p))
    return Workspace(root=p, meta=meta, cleanup=False)


def from_github(url: str, timeout: int = 120) -> Workspace:
    url = url.strip()
    if not (url.startswith(("http://", "https://", "git@")) or _GIT_HOST_RE.search(url)):
        raise ValueError("That does not look like a git repository URL.")

    tmp = Path(tempfile.mkdtemp(prefix="vibeaudit_"))
    dest = tmp / "repo"
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--no-tags", "--single-branch", url, str(dest)],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except FileNotFoundError:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ValueError("git is not installed or not on PATH.")
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ValueError("git clone timed out.")
    except subprocess.CalledProcessError as e:
        shutil.rmtree(tmp, ignore_errors=True)
        detail = (e.stderr or "").strip()[:300]
        raise ValueError(f"git clone failed: {detail}")

    commit = _short_commit(dest)
    name = url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    meta = ScanInputMeta(kind="github", name=name or "repo", detail=url, commit=commit)
    return Workspace(root=dest, meta=meta, cleanup=True)


def from_paste(code: str, filename: str | None = None, language_hint: str | None = None) -> Workspace:
    tmp = Path(tempfile.mkdtemp(prefix="vibeaudit_"))
    if filename:
        safe = Path(filename).name or "snippet.txt"
    else:
        ext = _EXT_BY_HINT.get((language_hint or "").lower(), ".txt")
        safe = f"snippet{ext}"
    (tmp / safe).write_text(code, encoding="utf-8")
    meta = ScanInputMeta(kind="paste", name=safe, detail=f"{len(code)} chars")
    return Workspace(root=tmp, meta=meta, cleanup=True)


def _short_commit(repo: Path) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None
