"""Shared helpers for locating a repository's working tree on disk."""

import re
from pathlib import Path

from ..config import DASHBOARD_DIR

_SLUG = re.compile(r"[^A-Za-z0-9_.-]+")


def slug(source: str) -> str:
    cleaned = source.rstrip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
    cleaned = cleaned.split("://", 1)[-1]
    if cleaned.startswith("git@"):
        cleaned = cleaned.split(":", 1)[-1]
    return _SLUG.sub("__", cleaned).strip("_")[:120] or "repository"


def cached_clone_path(source: str) -> Path:
    """Deterministic cache location for a remote repository clone."""
    return DASHBOARD_DIR / "data" / "repos" / slug(source)


def repository_dir(repository: dict) -> Path | None:
    """Return the on-disk working tree for a repository, if one is available.

    Local repositories map to their own path; remote repositories map to the
    cached clone created on first scan. Returns ``None`` when nothing is on disk
    (a remote repository that has never been scanned).
    """
    source = repository.get("source") or ""
    if repository.get("source_type") == "local":
        path = Path(source)
        return path if path.is_dir() else None
    path = cached_clone_path(source)
    return path if path.is_dir() else None
