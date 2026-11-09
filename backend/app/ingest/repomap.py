"""Discover, filter, and chunk source files from a workspace into a Repo."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from app.config import settings
from app.models.findings import RepoFileInfo, RepoMap
from app.util import looks_binary, truncate

# Directories we never descend into.
EXCLUDE_DIRS = {
    "node_modules", "dist", "build", "out", "coverage", "vendor", "target",
    "__pycache__", "migrations", "fixtures", "__snapshots__", "test-results",
}

# Files that are large/noise and never worth analyzing.
EXCLUDE_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Pipfile.lock", "composer.lock", "bun.lockb",
}

LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "typescript", ".tsx": "typescript", ".vue": "vue",
    ".svelte": "svelte", ".astro": "astro", ".html": "html", ".htm": "html",
    ".css": "css", ".scss": "css", ".sass": "css", ".json": "json", ".go": "go",
    ".rb": "ruby", ".php": "php", ".java": "java", ".cs": "csharp", ".sql": "sql",
    ".sh": "shell", ".bash": "shell", ".yml": "yaml", ".yaml": "yaml", ".toml": "toml",
}

MANIFEST_NAMES = {
    "package.json", "requirements.txt", "pyproject.toml", "Pipfile", "go.mod",
    "composer.json", "Gemfile", "docker-compose.yml", "docker-compose.yaml",
    "vite.config.js", "vite.config.ts", "next.config.js", "next.config.mjs",
    "tsconfig.json", "vercel.json", "netlify.toml",
}

# Languages we send to the LLM for deep analysis (config/data handled by triage + secret scan).
ANALYZABLE_LANGS = {
    "python", "javascript", "typescript", "vue", "svelte", "astro", "html",
    "go", "ruby", "php", "java", "csharp",
}

# Path substrings that flag high-risk code worth prioritizing.
PRIORITY_HINTS = [
    "auth", "login", "signup", "session", "token", "password", "secret", "crypto",
    "api", "route", "controller", "handler", "server", "middleware", "admin",
    "db", "database", "query", "sql", "model", "upload", "payment", "checkout",
    "user", "account", "config", "env", "webhook",
]

ENTRY_STEMS = {"main", "app", "index", "server", "wsgi", "asgi", "manage"}


@dataclass
class SourceFile:
    rel: str
    abspath: Path
    language: str
    text: str
    bytes: int
    lines: int
    is_manifest: bool
    priority: float


@dataclass
class Repo:
    root: Path
    files: list[SourceFile] = field(default_factory=list)
    truncated: bool = False

    def manifests(self) -> list[SourceFile]:
        return [f for f in self.files if f.is_manifest]

    def analyzable(self) -> list[SourceFile]:
        return [f for f in self.files if f.language in ANALYZABLE_LANGS]

    def to_map(self) -> RepoMap:
        langs: dict[str, int] = {}
        for f in self.files:
            langs[f.language] = langs.get(f.language, 0) + 1
        return RepoMap(
            root_name=self.root.name,
            files=[
                RepoFileInfo(path=f.rel, language=f.language, bytes=f.bytes,
                             lines=f.lines, is_manifest=f.is_manifest)
                for f in self.files
            ],
            total_bytes=sum(f.bytes for f in self.files),
            total_files=len(self.files),
            truncated=self.truncated,
            languages=langs,
        )

    def map_text(self, limit: int = 400) -> str:
        rows = []
        for f in sorted(self.files, key=lambda x: x.rel)[:limit]:
            star = " *" if f.is_manifest else ""
            rows.append(f"{f.rel}  [{f.language}, {f.lines} lines]{star}")
        if len(self.files) > limit:
            rows.append(f"... and {len(self.files) - limit} more files")
        return "\n".join(rows)

    def manifests_text(self, char_limit: int = 12000) -> str:
        parts, used = [], 0
        for f in self.manifests():
            block = f"--- {f.rel} ---\n{truncate(f.text, 3000)}"
            if used + len(block) > char_limit:
                break
            parts.append(block)
            used += len(block)
        return "\n\n".join(parts) if parts else "(no manifest files found)"


def _language_for(path: Path) -> str | None:
    ext = path.suffix.lower()
    if ext in LANG_BY_EXT:
        return LANG_BY_EXT[ext]
    name = path.name
    if name in MANIFEST_NAMES:
        return "config"
    if name.lower().startswith("dockerfile"):
        return "dockerfile"
    if name == ".env" or name.startswith(".env."):
        return "dotenv"
    return None


def _priority(rel: str, language: str, is_manifest: bool) -> float:
    score = 0.0
    if language in ("python", "javascript", "typescript", "go", "php", "ruby", "java", "csharp"):
        score += 3.0
    elif language in ("vue", "svelte", "astro", "html"):
        score += 1.5
    low = rel.lower()
    score += sum(1.0 for hint in PRIORITY_HINTS if hint in low)
    if Path(rel).stem.lower() in ENTRY_STEMS:
        score += 2.0
    if is_manifest:
        score += 0.5
    return score


def build_repo(root: Path | str) -> Repo:
    root = Path(root)
    files: list[SourceFile] = []
    total = 0
    truncated = False
    hard_cap = settings.max_files * 3  # collect a bit more than we analyze

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune excluded + hidden directories in place (fast; avoids node_modules, .git).
        dirnames[:] = [
            d for d in dirnames if d not in EXCLUDE_DIRS and not d.startswith(".")
        ]
        for name in sorted(filenames):
            if name in EXCLUDE_FILES:
                continue
            p = Path(dirpath) / name
            language = _language_for(p)
            if language is None:
                continue
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if size > settings.max_file_bytes:
                continue
            if total + size > settings.max_total_bytes or len(files) >= hard_cap:
                truncated = True
                break
            try:
                raw = p.read_bytes()
            except OSError:
                continue
            if looks_binary(raw):
                continue
            text = raw.decode("utf-8", errors="replace")
            rel = p.relative_to(root).as_posix()
            is_manifest = (
                name in MANIFEST_NAMES or language in ("config", "dockerfile", "dotenv")
            )
            lines = text.count("\n") + 1
            files.append(
                SourceFile(
                    rel=rel, abspath=p, language=language, text=text, bytes=size,
                    lines=lines, is_manifest=is_manifest,
                    priority=_priority(rel, language, is_manifest),
                )
            )
            total += size
        if truncated:
            break

    return Repo(root=root, files=files, truncated=truncated)


def chunk_source(sf: SourceFile) -> list[tuple[int, int, str]]:
    """Split a file into (start_line, end_line, text) chunks with overlap."""
    lines = sf.text.splitlines()
    n = len(lines)
    if n == 0:
        return [(1, 1, "")]
    if n <= settings.chunk_lines:
        return [(1, n, sf.text)]

    chunks: list[tuple[int, int, str]] = []
    start = 0
    while start < n and len(chunks) < settings.max_chunks_per_file:
        end = min(start + settings.chunk_lines, n)
        chunks.append((start + 1, end, "\n".join(lines[start:end])))
        if end >= n:
            break
        start = end - settings.chunk_overlap
    return chunks
