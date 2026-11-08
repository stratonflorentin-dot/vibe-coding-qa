"""Dashboard aggregation routes (overview cards, charts and the activity feed)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from ..schemas import ActivityOut, OverviewOut
from .deps import Services, get_services

router = APIRouter(tags=["dashboard"])

ServicesDep = Annotated[Services, Depends(get_services)]


@router.get("/api/dashboard/overview", response_model=OverviewOut)
def overview(
    services: ServicesDep,
    repository_id: int | None = None,
) -> dict:
    """Overview metrics derived from persisted scans only.

    ``has_data`` is false and every series is empty until a scan has actually
    completed — the dashboard never renders invented numbers.
    """
    if repository_id is not None:
        services.repositories.require(repository_id)
    return services.dashboard.overview(repository_id)


@router.get("/api/dashboard/activity", response_model=ActivityOut)
def activity(services: ServicesDep, limit: int = Query(default=30, ge=1, le=100)) -> dict:
    return services.dashboard.activity(limit)
