"""Vibe Intelligence: the modular intelligence service inside Vibe Coding QA.

v1 (Intelligence Core) provides typed task contracts, a provider/model registry,
deterministic task routing, a redacted project-context engine, and a gateway
that orchestrates deterministic and AI-backed operations over the existing AI
provider — without replacing any existing capability or applying code itself.
"""

from .contracts import (
    IntelligenceRequest,
    IntelligenceResult,
    Operation,
    TaskStatus,
)
from .exceptions import IntelligenceError
from .gateway import IntelligenceGateway

__all__ = [
    "IntelligenceError",
    "IntelligenceGateway",
    "IntelligenceRequest",
    "IntelligenceResult",
    "Operation",
    "TaskStatus",
]
