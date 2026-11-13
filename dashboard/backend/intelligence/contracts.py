"""Typed request/response contracts for Vibe Intelligence tasks.

Requests are validated with Pydantic (already used across the backend). Results
share one envelope: a status, a confidence level that is explicitly separate
from any model's self-reported certainty, validated evidence references that
must point at real files/findings/scans, and an operation-specific ``data``
payload. Nothing here fabricates execution results.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Operation(str, Enum):
    ANALYZE_PROJECT = "analyze_project"
    DISCOVER_FEATURES = "discover_features"
    MAP_ARCHITECTURE = "map_architecture"
    GENERATE_TEST_PLAN = "generate_test_plan"
    DIAGNOSE_FAILURE = "diagnose_failure"
    PROPOSE_REPAIR = "propose_repair"
    ANALYZE_REGRESSION = "analyze_regression"
    SUMMARIZE_VERIFICATION = "summarize_verification"
    ASSISTANT_CHAT = "assistant_chat"


class TaskStatus(str, Enum):
    COMPLETED = "completed"
    PARTIAL = "partial"            # produced evidence, but not a full AI answer
    UNAVAILABLE = "unavailable"    # no capable provider configured
    FAILED = "failed"


class ExecutionKind(str, Enum):
    DETERMINISTIC = "deterministic"
    AI = "ai"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class EvidenceKind(str, Enum):
    FILE = "file"
    FINDING = "finding"
    SCAN = "scan"
    TEST = "test"
    DEPENDENCY = "dependency"
    ARCHITECTURE = "architecture"
    LOG = "log"


class EvidenceRef(BaseModel):
    """A pointer to real evidence. Never a made-up path or id."""

    kind: EvidenceKind
    ref: str = Field(max_length=512)
    line: int | None = None
    detail: str | None = Field(default=None, max_length=500)


class ContextOptions(BaseModel):
    """What context the caller permits. Defaults to the minimum necessary.

    Source-file contents stay OFF unless explicitly enabled, matching the
    existing ``share_source_context`` posture.
    """

    repository_metadata: bool = True
    findings: bool = True
    scan_report: bool = True
    dependencies: bool = False
    architecture: bool = False
    source_files: bool = False
    max_files: int = Field(default=6, ge=0, le=40)
    max_chars: int = Field(default=20_000, ge=1_000, le=200_000)


class IntelligenceRequest(BaseModel):
    """One structured intelligence request."""

    operation: Operation
    repository_id: int | None = Field(default=None, ge=1)
    scan_id: int | None = Field(default=None, ge=1)
    finding_id: int | None = Field(default=None, ge=1)
    base_scan_id: int | None = Field(default=None, ge=1)
    head_scan_id: int | None = Field(default=None, ge=1)
    branch: str | None = Field(default=None, max_length=200)
    commit: str | None = Field(default=None, max_length=64)
    scope: str | None = Field(default=None, max_length=200)
    question: str | None = Field(default=None, max_length=4_000)
    conversation_id: int | None = Field(default=None, ge=1)
    context: ContextOptions = Field(default_factory=ContextOptions)
    max_output_tokens: int | None = Field(default=None, ge=16, le=16_000)


class IntelligenceResult(BaseModel):
    """The envelope every task returns."""

    task_id: int | None = None
    operation: Operation
    status: TaskStatus
    execution_kind: ExecutionKind
    confidence: Confidence = Confidence.UNKNOWN
    summary: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    provider: str | None = None
    model: str | None = None
    fallback_used: bool = False
    latency_ms: int | None = None


#: Which identifiers each operation requires. The gateway enforces this.
REQUIRED_FIELDS: dict[Operation, tuple[str, ...]] = {
    Operation.ANALYZE_PROJECT: ("repository_id",),
    Operation.DISCOVER_FEATURES: ("repository_id",),
    Operation.MAP_ARCHITECTURE: ("repository_id",),
    Operation.GENERATE_TEST_PLAN: ("repository_id",),
    Operation.DIAGNOSE_FAILURE: ("finding_id",),
    Operation.PROPOSE_REPAIR: ("finding_id",),
    Operation.ANALYZE_REGRESSION: ("base_scan_id", "head_scan_id"),
    Operation.SUMMARIZE_VERIFICATION: ("scan_id",),
    Operation.ASSISTANT_CHAT: ("question",),
}


__all__ = [
    "Confidence",
    "ContextOptions",
    "EvidenceKind",
    "EvidenceRef",
    "ExecutionKind",
    "IntelligenceRequest",
    "IntelligenceResult",
    "Operation",
    "REQUIRED_FIELDS",
    "TaskStatus",
]
