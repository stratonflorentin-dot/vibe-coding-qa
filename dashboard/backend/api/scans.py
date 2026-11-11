"""Scan routes: create, list, inspect, cancel, diff, and stream live events."""

from __future__ import annotations

import asyncio
import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from ..profiles import get_profile
from ..schemas import GenericMessage, ScanCreate, ScanEventOut, ScanListOut, ScanOut
from ..security import ValidationError
from ..services.intel import compare_scans
from ..services.settings import scan_settings
from .deps import Services, get_services

router = APIRouter(tags=["scans"])

ServicesDep = Annotated[Services, Depends(get_services)]

_TERMINAL = {"completed", "failed", "cancelled"}
_POLL_SECONDS = 0.5
_MAX_STREAM_SECONDS = 60 * 60


# NOTE: this must be declared before ``/api/scans/{scan_id}`` so that "compare"
# is not parsed as a scan id.
@router.get("/api/scans/compare")
def diff_scans(
    services: ServicesDep,
    base: int = Query(description="Baseline scan id"),
    head: int = Query(description="Scan id to compare against the baseline"),
) -> dict:
    if base == head:
        raise ValidationError("Pick two different scans to compare.")
    return compare_scans(services.store, base, head)


@router.post("/api/scans", response_model=ScanOut, status_code=202)
def create_scan(payload: ScanCreate, services: ServicesDep) -> dict:
    """Queue a scan. It runs in the bounded background pool, not in this request."""
    repository = services.repositories.require(payload.repository_id)
    defaults = scan_settings(services.store, services.settings)

    profile_key = (payload.profile or defaults["default_scan_profile"]).strip()
    try:
        get_profile(profile_key)
    except KeyError as exc:
        raise ValidationError(f"Unknown scan profile: {profile_key}") from exc

    options = payload.options.model_dump(exclude_none=True)
    try:
        return services.scans.create(repository=repository, profile_key=profile_key, options=options)
    except RuntimeError as exc:  # the queue is bounded on purpose
        raise HTTPException(status_code=429, detail=str(exc)) from exc


@router.get("/api/scans", response_model=ScanListOut)
def list_scans(
    services: ServicesDep,
    repository_id: int | None = None,
    status: str | None = Query(default=None, pattern="^(queued|running|completed|failed|cancelled)$"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict:
    items, total = services.store.list_scans(
        repository_id=repository_id, status=status, limit=limit, offset=offset
    )
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/api/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, services: ServicesDep) -> dict:
    scan = services.store.get_scan(scan_id)
    if scan is None:
        raise KeyError(f"Scan {scan_id} was not found.")
    return scan


@router.post("/api/scans/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(scan_id: int, services: ServicesDep) -> dict:
    """Cancel a scan that has not started yet.

    A scan already executing inside the sandbox is left to finish: interrupting
    it mid-run would risk leaving the engine in an inconsistent state.
    """
    scan = services.scans.cancel(scan_id)
    if scan is None:
        raise KeyError(f"Scan {scan_id} was not found.")
    return scan


@router.delete("/api/scans/{scan_id}", response_model=GenericMessage)
def delete_scan(scan_id: int, services: ServicesDep) -> dict:
    """Delete one scan from the history, along with its findings and events."""
    if services.store.get_scan(scan_id) is None:
        raise KeyError(f"Scan {scan_id} was not found.")
    try:
        services.scans.delete(scan_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"detail": "Scan and its findings were deleted."}


@router.get("/api/scans/{scan_id}/events.json", response_model=list[ScanEventOut])
def scan_events_snapshot(
    scan_id: int,
    services: ServicesDep,
    after: int = Query(default=0, ge=0),
) -> list[dict]:
    """Every persisted event for a scan (used for polling and by the tests)."""
    if services.store.get_scan(scan_id) is None:
        raise KeyError(f"Scan {scan_id} was not found.")
    return services.store.list_events(scan_id, after_id=after)


@router.get("/api/scans/{scan_id}/events")
async def scan_events_stream(scan_id: int, request: Request, services: ServicesDep, after: int = 0):
    """Server-Sent Events for a scan.

    Only events the engine actually emitted are sent: the dashboard never
    fabricates progress. The stream ends once the scan reaches a terminal state
    and every event has been delivered.
    """
    if services.store.get_scan(scan_id) is None:
        raise KeyError(f"Scan {scan_id} was not found.")

    return StreamingResponse(
        _event_stream(request, services, scan_id, after),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


async def _event_stream(request: Request, services: Services, scan_id: int, after: int):
    last_id = max(0, after)
    elapsed = 0.0
    yield _sse("open", {"scan_id": scan_id})
    while True:
        if await request.is_disconnected():
            return

        events = services.store.list_events(scan_id, after_id=last_id)
        if events:
            for event in events:
                last_id = event["id"]
                yield _sse("scan-event", {
                    "id": event["id"],
                    "scan_id": event["scan_id"],
                    "ts": event["ts"],
                    "stage": event["stage"],
                    "status": event.get("status"),
                    "message": event.get("message"),
                    "data": event.get("data") or {},
                })
            continue

        scan = services.store.get_scan(scan_id)
        status = (scan or {}).get("status")
        if status in _TERMINAL:
            yield _sse("end", {"scan_id": scan_id, "status": status})
            return
        if status is None:
            yield _sse("end", {"scan_id": scan_id, "status": "missing"})
            return

        elapsed += _POLL_SECONDS
        if elapsed >= _MAX_STREAM_SECONDS:
            yield _sse("end", {"scan_id": scan_id, "status": status, "reason": "stream-timeout"})
            return

        # Comment frame keeps proxies and browsers from closing the connection.
        yield ": keep-alive\n\n"
        await asyncio.sleep(_POLL_SECONDS)


def _sse(event: str, payload: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
