"""Vibe Coding QA dashboard (backend API + web UI).

The dashboard is an optional layer on top of the ``vibe_coding_qa`` engine: the
engine stays the single source of truth for scanning, scoring and the release
gate, and every dashboard feature works without AI.
"""

from vibe_coding_qa import __version__

__all__ = ["__version__"]
