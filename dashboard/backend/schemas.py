"""Request/response schemas for the dashboard API (Pydantic v2)."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


SourceType = Literal["local", "github", "url"]
ScanStatus = Literal["queued", "running", "completed", "failed", "cancelled"]
FindingStatus = Literal["open", "reviewed", "resolved", "dismissed", "unverified"]
Severity = Literal["critical", "high", "medium", "low", "info"]


class ErrorResponse(BaseModel):
    detail: str
    code: str = "error"


# ------------------------------------------------------------------ repositories
class RepositoryCreate(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    source: str = Field(min_length=1, max_length=500)
    source_type: SourceType = "local"

    @field_validator("source")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()


class LatestScanSummary(BaseModel):
    id: int
    status: ScanStatus
    overall_score: float | None = None
    gate: str | None = None
    critical_count: int | None = None
    high_count: int | None = None
    completed_at: str | None = None
    created_at: str | None = None
    test_status: str | None = None


class RepositoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    source: str
    source_type: str
    created_at: str
    updated_at: str
    main_language: str | None = None
    frameworks: list[str] = Field(default_factory=list)
    package_manager: str | None = None
    database_tech: list[str] = Field(default_factory=list)
    auth_tech: list[str] = Field(default_factory=list)
    deployment: list[str] = Field(default_factory=list)
    default_branch: str | None = None
    last_commit_sha: str | None = None
    last_scan_id: int | None = None
    latest_scan: LatestScanSummary | None = None


# ------------------------------------------------------------------------- scans
class ScanOptions(BaseModel):
    """Per-scan overrides.

    Resource fields default to ``None`` so "not specified" is distinguishable
    from "explicitly set": omitted values fall back to the operator's persisted
    scan settings (see ``services.settings``), which is what makes the scan
    settings screen functional rather than decorative.
    """

    static_only: bool = False
    explicit_permission: bool = False
    test_timeout: int | None = Field(default=None, ge=1, le=7200)
    test_image: str | None = None
    test_command: str | None = None
    max_memory_mb: int | None = Field(default=None, ge=64, le=16384)
    max_cpu_seconds: int | None = Field(default=None, ge=1, le=3600)
    max_snapshot_mb: int | None = Field(default=None, ge=1, le=2048)
    max_write_mb: int | None = Field(default=None, ge=2, le=2048)
    osv: bool | None = None
    ai_review: bool | None = None
    pentagi: bool = False
    share_source_context: bool = False


class ScanCreate(BaseModel):
    repository_id: int
    profile: str = "standard"
    options: ScanOptions = Field(default_factory=ScanOptions)


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    repository_id: int
    repository_name: str | None = None
    repository_source: str | None = None
    status: ScanStatus
    profile: str
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    commit_sha: str | None = None
    overall_score: float | None = None
    gate: str | None = None
    critical_count: int | None = 0
    high_count: int | None = 0
    total_findings: int | None = 0
    test_status: str | None = None
    tests_executed: int | None = None
    tests_passed: int | None = None
    tests_failed: int | None = None
    tests_skipped: int | None = None
    duration_ms: int | None = None
    scanner_versions: dict[str, Any] = Field(default_factory=dict)
    coverage_gaps: list[str] = Field(default_factory=list)
    ai_review_status: str | None = None
    error: str | None = None
    options: dict[str, Any] = Field(default_factory=dict)


class ScanListOut(BaseModel):
    items: list[ScanOut]
    total: int
    limit: int
    offset: int


class ScanEventOut(BaseModel):
    id: int
    scan_id: int
    ts: str
    stage: str
    status: str | None = None
    message: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------- findings
class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    repository_id: int
    repository_name: str | None = None
    fingerprint: str
    rule: str
    module: str
    severity: Severity
    file: str
    line: int
    column: int = 0
    message: str | None = ""
    suggestion: str | None = ""
    confidence: str | None = "medium"
    fixable: int = 0
    status: FindingStatus
    first_seen_scan_id: int | None = None
    created_at: str


class FindingDetailOut(FindingOut):
    scan_profile: str | None = None
    scan_completed_at: str | None = None
    evidence: list[str] = Field(default_factory=list)
    history: list[dict[str, Any]] = Field(default_factory=list)
    related: list[dict[str, Any]] = Field(default_factory=list)
    latest_ai_review: dict[str, Any] | None = None


class FindingListOut(BaseModel):
    items: list[FindingOut]
    total: int
    limit: int
    offset: int


class FindingStatusUpdate(BaseModel):
    status: Literal["open", "reviewed", "dismissed", "unverified"]


# ---------------------------------------------------------------------- dashboard
class SummaryCards(BaseModel):
    overall_score: float | None
    critical: int
    high: int
    total_open: int
    tests_executed: int | None
    tests_passed: int | None
    gate: str | None
    repository_count: int
    latest_scan_duration_ms: int | None


class OverviewOut(BaseModel):
    summary: SummaryCards
    severity_breakdown: dict[str, int]
    category_breakdown: dict[str, int]
    score_history: list[dict[str, Any]]
    findings_trend: list[dict[str, Any]]
    test_history: list[dict[str, Any]]
    repository_health: list[dict[str, Any]]
    has_data: bool


class ActivityItem(BaseModel):
    kind: str
    title: str
    detail: str
    at: str | None
    repository_id: int | None = None
    scan_id: int | None = None
    finding_id: int | None = None
    severity: str | None = None


class ActivityOut(BaseModel):
    items: list[ActivityItem]


# ---------------------------------------------------------------------------- AI
class AIChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=8000)
    repository_id: int | None = None
    conversation_id: int | None = None


class AIMessageOut(BaseModel):
    id: int
    role: str
    content: str
    created_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AIChatResponse(BaseModel):
    conversation_id: int
    message: AIMessageOut
    configured: bool
    sources: list[dict[str, Any]] = Field(default_factory=list)


class AIConversationOut(BaseModel):
    id: int
    repository_id: int | None
    title: str
    created_at: str
    updated_at: str
    messages: list[AIMessageOut] = Field(default_factory=list)


class AIReviewRequest(BaseModel):
    kind: Literal["analyst", "explain", "impact"] = "analyst"


class AIReviewOut(BaseModel):
    finding_id: int
    configured: bool
    provider: str | None = None
    model: str | None = None
    error: str | None = None
    content: dict[str, Any] = Field(default_factory=dict)


class RemediationProposeRequest(BaseModel):
    finding_id: int


class RemediationOut(BaseModel):
    id: int
    finding_id: int | None
    repository_id: int
    status: str
    created_at: str
    updated_at: str
    provider: str | None = None
    model: str | None = None
    file: str | None = None
    original: str | None = None
    proposed: str | None = None
    diff: str | None = None
    rationale: str | None = None
    error: str | None = None
    history: list[dict[str, Any]] = Field(default_factory=list)


class ApproveRequest(BaseModel):
    confirm: bool = Field(description="Must be true; the user acknowledges the patch is applied to the working tree.")
    run_tests: bool = False
    explicit_permission: bool = False


class TestGenerateRequest(BaseModel):
    finding_id: int


class TestGenerateOut(BaseModel):
    finding_id: int
    configured: bool
    file_path: str | None = None
    content: str | None = None
    error: str | None = None
    note: str = ""


# --------------------------------------------------------------------- architecture
class ArchitectureNode(BaseModel):
    id: str
    kind: str
    label: str
    files: list[str] = Field(default_factory=list)
    confidence: str = "static"
    details: dict[str, Any] = Field(default_factory=dict)


class ArchitectureEdge(BaseModel):
    source: str
    target: str
    kind: str


class ArchitectureOut(BaseModel):
    repository_id: int
    nodes: list[ArchitectureNode]
    edges: list[ArchitectureEdge]
    findings_by_node: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


# ------------------------------------------------------------------- dependencies
class DependencyOut(BaseModel):
    name: str
    version: str | None = None
    direct: bool = True
    license: str | None = None
    advisories: list[dict[str, Any]] = Field(default_factory=list)
    status: str = "unknown"


class DependenciesOut(BaseModel):
    repository_id: int
    package_manager: str | None = None
    lockfiles: list[str] = Field(default_factory=list)
    dependencies: list[DependencyOut] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    osv_checked: bool = False


# ----------------------------------------------------------------------- settings
class LoginIn(BaseModel):
    username: str = Field(default="", max_length=200)
    password: str = Field(default="", max_length=500)


class AuthStatusOut(BaseModel):
    auth_required: bool
    authenticated: bool


class AISettingsIn(BaseModel):
    enabled: bool = False
    provider: str = Field(default="openrouter", max_length=60)
    base_url: str = Field(default="https://openrouter.ai/api/v1", max_length=300)
    model: str = Field(default="", max_length=200)
    timeout: int = Field(default=30, ge=1, le=600)
    max_output_tokens: int = Field(default=3000, ge=1, le=16000)
    share_source_context: bool = False
    # Optional. Held in process memory only; never persisted or echoed back.
    # An empty string means "leave the existing key unchanged"; use clear_api_key
    # to remove it.
    api_key: str = Field(default="", max_length=512)
    clear_api_key: bool = False


class AISettingsOut(BaseModel):
    enabled: bool
    provider: str
    base_url: str
    model: str
    timeout: int
    max_output_tokens: int
    share_source_context: bool
    api_key_configured: bool
    source: Literal["environment", "settings", "none"]


class ScanSettingsIn(BaseModel):
    default_scan_profile: str = "standard"
    allow_test_execution: bool = False
    test_image: str = Field(default="python:3.12-slim", max_length=200)
    test_timeout: int = Field(default=300, ge=1, le=7200)
    max_memory_mb: int = Field(default=512, ge=64, le=16384)
    max_cpu_seconds: int = Field(default=60, ge=1, le=3600)
    max_snapshot_mb: int = Field(default=256, ge=1, le=2048)
    max_write_mb: int = Field(default=64, ge=2, le=2048)
    osv_enabled: bool = True


class ScanSettingsOut(ScanSettingsIn):
    pass


class AIConnectionTestOut(BaseModel):
    ok: bool
    configured: bool
    provider: str | None = None
    model: str | None = None
    detail: str


class ConversationOut(BaseModel):
    id: int
    repository_id: int | None = None
    title: str
    created_at: str
    updated_at: str
    message_count: int = 0


class SummaryRequest(BaseModel):
    repository_id: int | None = None
    scan_id: int | None = None


class SummaryOut(BaseModel):
    configured: bool
    provider: str | None = None
    model: str | None = None
    error: str | None = None
    text: str = ""


class ThreatModelRequest(BaseModel):
    repository_id: int


class ThreatModelOut(BaseModel):
    repository_id: int
    configured: bool
    provider: str | None = None
    model: str | None = None
    error: str | None = None
    text: str = ""
    note: str = ""


class HealthOut(BaseModel):
    status: str
    version: str
    database: str
    ai_configured: bool
    repositories: int
    scans: int


class GenericMessage(BaseModel):
    detail: str
