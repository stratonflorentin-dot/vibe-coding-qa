"""Internal Vibe Intelligence API.

Not exposed publicly by default (loopback dashboard, behind the session gate and
RBAC). Reads require any authenticated user; running a task requires at least a
security analyst. The health/provider endpoints never return secrets.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from ..intelligence.contracts import IntelligenceRequest
from .deps import get_services, require_analyst, require_viewer

router = APIRouter(prefix="/api/intelligence", tags=["intelligence"])


@router.get("/health")
def health(request: Request) -> dict:
    require_viewer(request)
    return get_services(request).intelligence.health()


@router.get("/providers")
def providers(request: Request) -> dict:
    require_viewer(request)
    return {"providers": get_services(request).intelligence.providers()}


@router.get("/models")
def models(request: Request) -> dict:
    require_viewer(request)
    return {"models": get_services(request).intelligence.models()}


@router.post("/tasks")
def run_task(payload: IntelligenceRequest, request: Request) -> dict:
    user = require_analyst(request)
    result = get_services(request).intelligence.execute(payload, user=user)
    return result.model_dump()


@router.get("/tasks/{task_id}")
def get_task(task_id: int, request: Request) -> dict:
    require_viewer(request)
    task = get_services(request).intelligence.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Intelligence task not found.")
    return task
