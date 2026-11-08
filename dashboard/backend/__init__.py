"""Vibe Coding QA dashboard backend (FastAPI + SQLite).

This package wraps the existing :mod:`vibe_coding_qa` engine behind a typed HTTP
API. It never re-implements scanning logic: the engine remains the single source
of truth for findings, scoring and the release gate.
"""

__all__ = ["__version__"]

# Kept in sync with vibe_coding_qa.cli and pyproject/CHANGELOG.
__version__ = "0.5.0"
