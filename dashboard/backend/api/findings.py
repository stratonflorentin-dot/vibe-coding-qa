"""Finding routes: filter, inspect with real source evidence, and triage."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from vibe_coding_qa.scanners import redact_secrets

from ..schemas import FindingDetailOut, FindingListOut, FindingOut, FindingStatusUpdate
from ..services.paths import repository_dir
from ..security import ValidationError, resolve_repo_file
from .deps import Services, get_services

router = APIRouter(tags=["findings"])

ServicesDep = Annotated[Services, Depends(get_services)]

_EVIDENCE_RADIUS = 12


@router.get("/api/findings", response_model=FindingListOut)
def list_findings(
    services: ServicesDep,
    repository_id: int | None = None,
    scan_id: int | None = None,
    severity: list[str] | None = Query(default=None),
    module: list[str] | None = Query(default=None),
    status: list[str] | None = Query(default=None),
    search: str | None = None,
    limit: int | None = Query(default=None, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict:
    """List findings.

    Without an explicit ``scan_id`` the store restricts results to the newest
    completed scan per repository, so the UI shows the current state instead of
    historical duplicates.
    """
    page_size = limit or services.settings.finding_page_size
    page_size = min(page_size, services.settings.max_page_size)
    items, total = services.store.list_findings(
        repository_id=repository_id,
        scan_id=scan_id,
        severity=severity,
        module=module,
        status=status,
        search=search,
        limit=page_size,
        offset=offset,
    )
    return {"items": items, "total": total, "limit": page_size, "offset": offset}


@router.get("/api/findings/{finding_id}", response_model=FindingDetailOut)
def get_finding(finding_id: int, services: ServicesDep) -> dict:
    finding = services.store.get_finding(finding_id)
    if finding is None:
        raise KeyError(f"Finding {finding_id} was not found.")

    detail = dict(finding)
    detail["evidence"] = _source_evidence(services, finding)
    detail["history"] = services.store.finding_history(finding["fingerprint"], finding["repository_id"])
    detail["related"] = services.store.findings_in_file(
        finding["repository_id"], finding["file"], exclude_id=finding_id
    )
    review = services.store.latest_ai_review(finding_id)
    detail["latest_ai_review"] = review
    return detail


@router.patch("/api/findings/{finding_id}", response_model=FindingOut)
def update_finding_status(
    finding_id: int, payload: FindingStatusUpdate, services: ServicesDep
) -> dict:
    """Triage a single finding. The status is local to the dashboard."""
    if services.store.get_finding(finding_id) is None:
        raise KeyError(f"Finding {finding_id} was not found.")
    return services.store.set_finding_status(finding_id, payload.status)


def _source_evidence(services: Services, finding: dict, radius: int = _EVIDENCE_RADIUS) -> list[str]:
    """Numbered, redacted lines around the finding, read from the working tree."""
    repository = services.store.get_repository(finding["repository_id"])
    if repository is None:
        return []
    root = repository_dir(repository)
    if root is None:
        return []
    try:
        target = resolve_repo_file(root, finding["file"])
    except (OSError, RuntimeError, ValueError, ValidationError):
        return []
    try:
        lines = target.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    index = max(0, int(finding["line"]) - 1)
    start = max(0, index - radius)
    end = min(len(lines), index + radius + 1)
    return [redact_secrets(f"{number + 1:>5}: {lines[number]}") for number in range(start, end)]
