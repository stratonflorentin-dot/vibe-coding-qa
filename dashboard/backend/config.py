"""Runtime configuration for the dashboard backend.

All settings are environment-driven so that credentials never live in the
repository or reach the browser. ``get_settings`` is cached; tests call
``reset_settings`` after mutating the environment.
"""

import os
import sys
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
DASHBOARD_DIR = BACKEND_DIR.parent
PROJECT_ROOT = DASHBOARD_DIR.parent

# The dashboard reuses the existing analysis engine in place; it is not a copy.
# Put the project root on ``sys.path`` so ``import vibe_coding_qa`` works no
# matter how the app is launched (``uvicorn``, ``python -m``, tests).
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _csv(name: str, default: list[str]) -> list[str]:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return list(default)
    return [part.strip() for part in raw.split(",") if part.strip()]


def _roots(name: str, default: list[Path]) -> list[Path]:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return list(default)
    roots: list[Path] = []
    for part in raw.split(os.pathsep):
        part = part.strip()
        if part:
            roots.append(Path(part).expanduser())
    return roots or list(default)


@dataclass
class Settings:
    """Immutable-ish runtime settings resolved from the environment."""

    host: str = "127.0.0.1"
    port: int = 8756
    db_path: Path = field(default_factory=lambda: DASHBOARD_DIR / "data" / "vcqa.sqlite3")

    # Only localhost origins are allowed by default. The frontend dev server and
    # the packaged static build are both served from localhost.
    cors_origins: list[str] = field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:8756",
            "http://127.0.0.1:8756",
        ]
    )

    # Registering a local repository is restricted to these roots to prevent
    # arbitrary filesystem access. Paths are resolved and checked against them.
    allowed_repo_roots: list[Path] = field(
        default_factory=lambda: [Path.home().resolve(), PROJECT_ROOT.resolve()]
    )

    max_concurrent_scans: int = 2
    finding_page_size: int = 50
    max_page_size: int = 200

    # AI is entirely optional; the scanner and gate work without it.
    ai_provider: str = ""
    ai_api_key: str = ""
    ai_base_url: str = "https://openrouter.ai/api/v1"
    ai_model: str = "openai/gpt-3.5-turbo"
    ai_timeout: int = 30
    ai_max_output_tokens: int = 3000
    ai_enable_source_context: bool = False
    ai_max_requests_per_minute: int = 20
    ai_max_input_chars: int = 40_000

    github_token: str = ""

    # Defaults surfaced to the scan UI (mirrors the CLI defaults).
    default_scan_profile: str = "standard"
    allow_test_execution: bool = False
    default_test_image: str = "python:3.12-slim"
    default_test_timeout: int = 300
    default_max_memory_mb: int = 512
    default_max_cpu_seconds: int = 60
    default_max_snapshot_mb: int = 256
    default_max_write_mb: int = 64
    default_osv_enabled: bool = True


def _build_settings() -> Settings:
    return Settings(
        host=os.environ.get("VCQA_DASHBOARD_HOST", "127.0.0.1"),
        port=_int("VCQA_DASHBOARD_PORT", 8756),
        db_path=Path(os.environ.get("VCQA_DASHBOARD_DB", str(DASHBOARD_DIR / "data" / "vcqa.sqlite3"))).expanduser(),
        cors_origins=_csv(
            "VCQA_DASHBOARD_CORS",
            [
                "http://localhost:5173",
                "http://127.0.0.1:5173",
                "http://localhost:8756",
                "http://127.0.0.1:8756",
            ],
        ),
        allowed_repo_roots=_roots(
            "VCQA_ALLOWED_REPO_ROOTS",
            [Path.home().resolve(), PROJECT_ROOT.resolve()],
        ),
        max_concurrent_scans=max(1, _int("VCQA_MAX_CONCURRENT_SCANS", 2)),
        finding_page_size=_int("VCQA_FINDING_PAGE_SIZE", 50),
        max_page_size=_int("VCQA_MAX_PAGE_SIZE", 200),
        ai_provider=os.environ.get("VCQA_AI_PROVIDER", ""),
        ai_api_key=os.environ.get("VCQA_AI_API_KEY", ""),
        ai_base_url=os.environ.get("VCQA_AI_BASE_URL", "https://openrouter.ai/api/v1"),
        ai_model=os.environ.get("VCQA_AI_MODEL", "openai/gpt-3.5-turbo"),
        ai_timeout=_int("VCQA_AI_TIMEOUT", 30),
        ai_max_output_tokens=_int("VCQA_AI_MAX_OUTPUT_TOKENS", 3000),
        ai_enable_source_context=_flag("VCQA_AI_ENABLE_SOURCE_CONTEXT", False),
        ai_max_requests_per_minute=_int("VCQA_AI_MAX_REQUESTS_PER_MINUTE", 20),
        ai_max_input_chars=_int("VCQA_AI_MAX_INPUT_CHARS", 40_000),
        github_token=os.environ.get("VCQA_GITHUB_TOKEN", "") or os.environ.get("GITHUB_TOKEN", ""),
        default_scan_profile=os.environ.get("VCQA_DEFAULT_SCAN_PROFILE", "standard"),
        allow_test_execution=_flag("VCQA_ALLOW_TEST_EXECUTION", False),
        default_test_image=os.environ.get("VCQA_TEST_CONTAINER_IMAGE", "python:3.12-slim"),
        default_test_timeout=_int("VCQA_TEST_TIMEOUT", 300),
        default_max_memory_mb=_int("VCQA_MAX_MEMORY_MB", 512),
        default_max_cpu_seconds=_int("VCQA_MAX_CPU_SECONDS", 60),
        default_max_snapshot_mb=_int("VCQA_MAX_SNAPSHOT_MB", 256),
        default_max_write_mb=_int("VCQA_MAX_WRITE_MB", 64),
        default_osv_enabled=_flag("VCQA_OSV_ENABLED", True),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return _build_settings()


def reset_settings() -> Settings:
    """Clear the cache (used by tests and on SIGHUP-style reloads)."""
    get_settings.cache_clear()
    return get_settings()


def ai_configured(settings: Settings | None = None) -> bool:
    settings = settings or get_settings()
    provider = settings.ai_provider.strip().lower()
    return bool(settings.ai_api_key) and provider not in ("", "none", "false", "0")
