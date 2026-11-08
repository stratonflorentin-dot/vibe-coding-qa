"""Architecture and dependency intelligence routes.

Both read only static evidence (the repository profile, resolved lockfiles and
the persisted findings of the latest scan). When the evidence is missing the
response says so rather than filling the gap with guesswork.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from ..schemas import ArchitectureOut, DependenciesOut
from ..services.intel import build_architecture, build_dependencies
from .deps import Services, get_services

router = APIRouter(tags=["intelligence"])

ServicesDep = Annotated[Services, Depends(get_services)]


@router.get("/api/architecture/{repository_id}", response_model=ArchitectureOut)
def architecture(repository_id: int, services: ServicesDep) -> dict:
    repository = services.repositories.require(repository_id)
    return build_architecture(services.store, repository)


@router.get("/api/dependencies/{repository_id}", response_model=DependenciesOut)
def dependencies(
    repository_id: int,
    services: ServicesDep,
    osv: bool = Query(default=False, description="Query the OSV advisory database (network access)"),
) -> dict:
    """Dependencies with resolved versions.

    OSV lookups are opt-in: a GET never performs network calls unless the caller
    asks for them explicitly.
    """
    repository = services.repositories.require(repository_id)
    return build_dependencies(services.store, repository, osv=osv)
