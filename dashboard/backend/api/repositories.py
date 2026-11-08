"""Repository routes: register, inspect, refresh and remove repositories."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from ..schemas import GenericMessage, RepositoryCreate, RepositoryOut, ScanListOut
from .deps import Services, get_services

router = APIRouter(tags=["repositories"])

ServicesDep = Annotated[Services, Depends(get_services)]


@router.get("/api/repositories", response_model=list[RepositoryOut])
def list_repositories(services: ServicesDep) -> list[dict]:
    return services.repositories.list()


@router.post("/api/repositories", response_model=RepositoryOut, status_code=201)
def create_repository(payload: RepositoryCreate, services: ServicesDep) -> dict:
    """Register a local directory or a remote git source.

    Nothing is cloned here: a remote repository is fetched the first time it is
    scanned, so registration never performs a surprise network operation.
    """
    return services.repositories.register(
        source=payload.source, source_type=payload.source_type, name=payload.name
    )


@router.get("/api/repositories/{repository_id}", response_model=RepositoryOut)
def get_repository(repository_id: int, services: ServicesDep) -> dict:
    return services.repositories.require(repository_id)


@router.post("/api/repositories/{repository_id}/refresh", response_model=RepositoryOut)
def refresh_repository(repository_id: int, services: ServicesDep) -> dict:
    return services.repositories.refresh(repository_id)


@router.delete("/api/repositories/{repository_id}", response_model=GenericMessage)
def delete_repository(repository_id: int, services: ServicesDep) -> dict:
    services.repositories.require(repository_id)
    services.repositories.delete(repository_id)
    return {"detail": "Repository and its scan history were deleted."}


@router.get("/api/repositories/{repository_id}/scans", response_model=ScanListOut)
def repository_scans(
    repository_id: int,
    services: ServicesDep,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict:
    services.repositories.require(repository_id)
    items, total = services.store.list_scans(
        repository_id=repository_id, limit=limit, offset=offset
    )
    return {"items": items, "total": total, "limit": limit, "offset": offset}
