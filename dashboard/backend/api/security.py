"""Security Lab API: allowlisted workers, authorized targets, scans and evidence."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from ..schemas import (
    GenericMessage,
    SecurityFindingStatusUpdate,
    SecurityScanCreate,
    SecurityTargetCreate,
    SecurityTargetCreateOut,
    SecurityWorkerCreate,
    SecurityWorkerUpdate,
)
from .deps import Services, get_services, require_admin, require_analyst

router = APIRouter(prefix="/api/security", tags=["security-lab"])

ServicesDep = Annotated[Services, Depends(get_services)]
AnalystDep = Annotated[dict, Depends(require_analyst)]
AdminDep = Annotated[dict, Depends(require_admin)]


@router.get("/profiles")
def profiles(services: ServicesDep) -> list[dict]:
    return services.security_lab.list_profiles()


@router.get("/summary")
def summary(services: ServicesDep, target_id: int | None = Query(default=None, ge=1)) -> dict:
    return services.security_lab.severity_counts(target_id)


@router.get("/workers")
def workers(services: ServicesDep) -> list[dict]:
    return services.security_lab.workers()


@router.post("/workers", status_code=201)
def create_worker(payload: SecurityWorkerCreate, services: ServicesDep, _user: AdminDep) -> dict:
    return services.security_lab.register_worker(**payload.model_dump())


@router.get("/workers/{worker_id}/status")
def worker_status(worker_id: int, services: ServicesDep) -> dict:
    return services.security_lab.worker_status(worker_id)


@router.patch("/workers/{worker_id}")
def update_worker(
    worker_id: int, payload: SecurityWorkerUpdate, services: ServicesDep, _user: AdminDep
) -> dict:
    return services.security_lab.update_worker(
        worker_id, **payload.model_dump(exclude_unset=True, exclude_none=True)
    )


@router.post("/workers/{worker_id}/revoke", response_model=GenericMessage)
def revoke_worker(worker_id: int, services: ServicesDep, _user: AdminDep) -> dict:
    return services.security_lab.revoke_worker(worker_id)


@router.delete("/workers/{worker_id}", response_model=GenericMessage)
def delete_worker(worker_id: int, services: ServicesDep, _user: AdminDep) -> dict:
    services.security_lab.delete_worker(worker_id)
    return {"detail": "Security worker deleted."}


@router.get("/targets")
def targets(services: ServicesDep) -> list[dict]:
    return services.security_lab.targets()


@router.post("/targets", status_code=201, response_model=SecurityTargetCreateOut)
def create_target(payload: SecurityTargetCreate, services: ServicesDep, user: AnalystDep) -> dict:
    return services.security_lab.register_target(**payload.model_dump(), actor=user)


@router.post("/targets/{target_id}/verify")
def verify_target(target_id: int, services: ServicesDep, _user: AnalystDep) -> dict:
    return services.security_lab.verify_target(target_id)


@router.delete("/targets/{target_id}", response_model=GenericMessage)
def delete_target(target_id: int, services: ServicesDep, _user: AdminDep) -> dict:
    services.security_lab.delete_target(target_id)
    return {"detail": "Authorized target removed."}


@router.post("/scans", status_code=202)
def start_scan(payload: SecurityScanCreate, services: ServicesDep, user: AnalystDep) -> dict:
    return services.security_lab.start_scan(**payload.model_dump(), actor=user)


@router.get("/jobs")
def jobs(
    services: ServicesDep,
    status: str | None = None,
    target_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict:
    items, total = services.security_lab.jobs(status=status, target_id=target_id, limit=limit, offset=offset)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/jobs/{job_id}")
def get_job(job_id: int, services: ServicesDep) -> dict:
    return services.security_lab.require_job(job_id)


@router.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: int, services: ServicesDep, _user: AnalystDep) -> dict:
    return services.security_lab.cancel_job(job_id)


@router.get("/findings")
def findings(
    services: ServicesDep,
    target_id: int | None = Query(default=None, ge=1),
    job_id: int | None = Query(default=None, ge=1),
    severity: str | None = None,
    status: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict:
    items, total = services.security_lab.findings(
        target_id=target_id,
        job_id=job_id,
        severity=severity,
        status=status,
        limit=limit,
        offset=offset,
    )
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/findings/{finding_id}")
def get_finding(finding_id: int, services: ServicesDep) -> dict:
    return services.security_lab.require_finding(finding_id)


@router.patch("/findings/{finding_id}")
def update_finding(
    finding_id: int,
    payload: SecurityFindingStatusUpdate,
    services: ServicesDep,
    _user: AnalystDep,
) -> dict:
    return services.security_lab.set_finding_status(finding_id, payload.status)


@router.post("/findings/{finding_id}/verify")
def verify_finding(finding_id: int, services: ServicesDep, user: AnalystDep) -> dict:
    return services.security_lab.verify_finding(finding_id, user)


@router.get("/evidence")
def evidence(
    services: ServicesDep,
    job_id: int | None = Query(default=None, ge=1),
    finding_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[dict]:
    rows = services.security_lab.evidence(job_id=job_id, finding_id=finding_id, limit=limit)
    return [{key: value for key, value in row.items() if key != "content"} for row in rows]


@router.get("/evidence/{evidence_id}")
def get_evidence(evidence_id: int, services: ServicesDep, _user: AnalystDep) -> dict:
    return services.security_lab.require_evidence(evidence_id)


@router.get("/report")
def report(
    services: ServicesDep,
    target_id: int | None = Query(default=None, ge=1),
) -> dict:
    return services.security_lab.report(target_id=target_id)
