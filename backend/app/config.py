"""Environment-driven configuration for VibeAudit.

Settings load from the project-root .env file (see .env.example). Every value has a
safe default so the app can import even before a key is configured.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/app/config.py -> parents[2] == project root (vibe-audit/)
PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        protected_namespaces=(),  # allow a field literally named `model`
    )

    # --- Mode ---
    # local:  your own machine. Folder, GitHub and Deep (Docker) scans are allowed; history is shared.
    # public: hosted for strangers. Pasted snippets only, rate-limited, results are private and expire.
    app_mode: Literal["local", "public"] = "local"

    # --- LLM (any OpenAI-compatible endpoint; NVIDIA Integrate by default) ---
    # LLM_API_KEY / LLM_BASE_URL work too, e.g. for OpenRouter.
    nvidia_api_key: str = Field("", validation_alias=AliasChoices("LLM_API_KEY", "NVIDIA_API_KEY"))
    nvidia_base_url: str = Field(
        "https://integrate.api.nvidia.com/v1",
        validation_alias=AliasChoices("LLM_BASE_URL", "NVIDIA_BASE_URL"),
    )
    model: str = "nvidia/nemotron-3-ultra-550b-a55b"
    # NVIDIA's Nemotron takes `chat_template_kwargs.enable_thinking`; other providers may reject it.
    send_thinking_flag: bool = True

    analysis_temperature: float = 0.2
    analysis_top_p: float = 0.95
    max_tokens: int = 8192
    enable_thinking: bool = True
    request_timeout: float = 180.0
    max_retries: int = 4

    # --- Scan limits (cost/speed knobs) ---
    max_concurrency: int = 4
    max_file_bytes: int = 120_000
    max_total_bytes: int = 5_000_000
    max_files: int = 40
    max_analysis_units: int = 120
    chunk_lines: int = 350
    chunk_overlap: int = 30
    max_chunks_per_file: int = 6

    # --- Features ---
    enable_deterministic: bool = True    # Phase 3: secret/bandit/semgrep pre-pass
    enable_verification: bool = True     # Phase 3: LLM false-positive verification
    enable_dynamic: bool = True          # Phase 4: run the app in Docker on a "deep" scan
    enable_browser_probe: bool = True    # Phase 4: Playwright console probe (if installed)

    # --- Dynamic sandbox (Phase 4) ---
    dynamic_timeout_s: int = 180
    dynamic_memory: str = "1g"
    dynamic_cpus: str = "1.0"
    dynamic_node_image: str = "node:20-slim"
    dynamic_python_image: str = "python:3.12-slim"
    dynamic_max_copy_bytes: int = 250_000_000

    # --- Snippet input limits (both modes) ---
    max_snippet_lines: int = 400
    max_snippet_bytes: int = 20_000
    max_request_bytes: int = 64_000      # whole POST body; anything larger is refused early

    # --- Abuse & cost controls (enforced in public mode) ---
    rate_limit_per_hour: int = 5         # new scans per client IP per rolling hour
    daily_scan_cap: int = 100            # new scans across all clients per UTC day
    max_running_scans: int = 2           # scans running at the same time
    trust_proxy_headers: bool = False    # use X-Forwarded-For (only behind your own proxy)
    scan_timeout_s: int = 300            # hard limit for one scan

    # --- Results ---
    result_ttl_hours: int = 24           # public mode: delete stored results after this (0 = keep)
    cache_ttl_hours: int = 24            # identical snippet within this window → reuse result
    job_retention_s: int = 600           # finished jobs stay in memory this long for SSE clients

    # --- Storage ---
    data_dir: Path = PROJECT_ROOT / "data"

    # --- Runtime ---
    # server: one long-running process (uvicorn). Jobs, limits and SQLite live in that process.
    # lambda: AWS Lambda. State lives in DynamoDB, a worker function runs each scan, and the
    #         browser polls for progress (a buffered Lambda response can't stream SSE).
    runtime: Literal["server", "lambda"] = "server"
    table_name: str = ""                 # DynamoDB table (lambda runtime)
    worker_function: str = ""            # name of the worker Lambda the API invokes
    llm_api_key_param: str = ""          # SSM SecureString holding the model key (lambda runtime)
    # Header that carries the real client IP, set by your CDN and not spoofable by the client,
    # e.g. "cloudfront-viewer-address" ("ip:port"). Empty = use the socket address.
    client_ip_header: str = ""
    # When set, every request must carry X-Origin-Verify with this value, so the Lambda URL
    # can only be reached through CloudFront (which adds the header).
    origin_secret: str = ""

    @property
    def public(self) -> bool:
        return self.app_mode == "public"

    @property
    def serverless(self) -> bool:
        return self.runtime == "lambda"

    @property
    def configured(self) -> bool:
        """True once an API key is present."""
        return bool(self.nvidia_api_key.strip())


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    try:
        s.data_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return s


settings = get_settings()
