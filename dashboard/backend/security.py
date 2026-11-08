"""Input validation, path safety, rate limiting and error hygiene.

The dashboard is bound to localhost by default, but it still must not become a
generic filesystem or network proxy. Everything a request can influence is
validated here before it reaches the engine:

* local repository paths must resolve to a directory inside an allow-listed root
  (no path traversal, no symlink escape);
* git sources must be well-formed and must never carry embedded credentials;
* AI calls are size-bounded and rate-limited;
* errors returned to the client are safe: no stack traces, no credentials, no
  local absolute paths from internals.
"""

import re
import threading
import time
from pathlib import Path

from vibe_coding_qa.repo import is_git_url
from vibe_coding_qa.scanners import redact_secrets


class ValidationError(ValueError):
    """Raised when a client-supplied value is rejected."""


_GITHUB_REF = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SSH_GITHUB_URL = re.compile(r"^git@github\.com:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?$")


def resolve_repo_path(source: str, allowed_roots: list[Path]) -> Path:
    """Validate a local repository path against the allow-listed roots.

    Rejects empty values, non-existent paths, non-directories, and any path that
    (after resolving symlinks) is not inside one of ``allowed_roots``.
    """
    candidate = (source or "").strip()
    if not candidate:
        raise ValidationError("Repository path is required.")
    if "\0" in candidate:
        raise ValidationError("Repository path contains an invalid character.")
    try:
        resolved = Path(candidate).expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValidationError(f"Repository path does not exist: {candidate}")
    if not resolved.is_dir():
        raise ValidationError(f"Repository path is not a directory: {candidate}")
    for root in allowed_roots:
        try:
            root_resolved = Path(root).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if resolved == root_resolved or root_resolved in resolved.parents:
            return resolved
    raise ValidationError(
        "Repository path is outside the allowed roots. Set VCQA_ALLOWED_REPO_ROOTS "
        "to permit additional directories."
    )


def resolve_repo_file(root: Path, relative_path: str) -> Path:
    """Resolve a repository-relative file and reject traversal or symlink escape."""
    candidate = Path(relative_path)
    if candidate.is_absolute():
        raise ValidationError("The requested file path must be relative to the repository.")
    try:
        resolved_root = root.resolve(strict=True)
        target = (resolved_root / candidate).resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValidationError("The requested file is not available in the repository.") from None
    if target == resolved_root or not target.is_relative_to(resolved_root) or not target.is_file():
        raise ValidationError("The requested file must be inside the repository.")
    return target


def validate_git_source(source: str) -> str:
    """Validate a remote git source and reject embedded credentials.

    Accepts ``owner/repo`` shorthand, an ``https://`` URL, or an SSH URL. A
    ``user:password@`` userinfo segment is rejected outright: credentials must be
    supplied out-of-band (``VCQA_GITHUB_TOKEN``) and never travel through the API.
    """
    candidate = (source or "").strip()
    if not candidate:
        raise ValidationError("Repository source is required.")
    if "@" in candidate.split("://", 1)[-1].split("/", 1)[0] and candidate.startswith("http"):
        raise ValidationError("Repository URLs must not contain embedded credentials.")
    if _GITHUB_REF.match(candidate):
        return candidate
    if not is_git_url(candidate):
        raise ValidationError("Source must be a local path, owner/repo, or a git URL.")
    if candidate.startswith(("http://", "https://")):
        from urllib.parse import urlsplit

        parsed = urlsplit(candidate)
        if parsed.username is not None or parsed.password is not None:
            raise ValidationError("Repository URLs must not contain embedded credentials.")
        if parsed.scheme != "https" or parsed.hostname != "github.com":
            raise ValidationError("Remote repositories must use HTTPS on github.com.")
        try:
            port = parsed.port
        except ValueError:
            raise ValidationError("GitHub repository URL has an invalid port.") from None
        if port not in (None, 443):
            raise ValidationError("GitHub repository URLs must use the standard HTTPS port.")
        if parsed.query or parsed.fragment or not re.fullmatch(
            r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?", parsed.path
        ):
            raise ValidationError("GitHub URLs must point directly to an owner/repository.")
    elif candidate.startswith("git@") and not _SSH_GITHUB_URL.fullmatch(candidate):
        raise ValidationError("SSH repository URLs must use the git@github.com:owner/repository format.")
    return candidate


class RateLimiter:
    """A simple thread-safe fixed-window rate limiter."""

    def __init__(self, max_requests: int, window_seconds: float = 60.0):
        self.max_requests = max(1, int(max_requests))
        self.window_seconds = float(window_seconds)
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str = "default") -> bool:
        now = time.monotonic()
        with self._lock:
            stamps = [t for t in self._hits.get(key, []) if now - t < self.window_seconds]
            if len(stamps) >= self.max_requests:
                self._hits[key] = stamps
                return False
            stamps.append(now)
            self._hits[key] = stamps
            return True


def bound_text(text: str | None, max_chars: int) -> str:
    """Redact secrets and enforce a hard character budget before egress."""
    value = redact_secrets(text or "")
    if len(value) > max_chars:
        value = value[:max_chars] + "\n...[truncated]"
    return value


def safe_error(exc: BaseException, fallback: str = "The operation failed.") -> str:
    """Return a client-safe error string.

    Known, deliberately raised messages (``ValidationError``/``KeyError``/
    ``FileNotFoundError`` created by this app) are surfaced; anything else is
    collapsed to a generic message so internal details never leak.
    """
    if isinstance(exc, KeyError):
        return str(exc.args[0]) if exc.args else "The requested item was not found."
    if isinstance(exc, ValidationError):
        return str(exc)
    if isinstance(exc, OSError) and getattr(exc, "strerror", None):
        return f"I/O error: {exc.strerror}"
    return fallback
