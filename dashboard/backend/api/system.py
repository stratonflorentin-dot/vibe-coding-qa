"""System routes: health, scan profiles, and operator settings."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from .. import __version__
from ..profiles import list_profiles
from ..schemas import (
    AIConnectionTestOut,
    AISettingsIn,
    AISettingsOut,
    HealthOut,
    ScanSettingsIn,
    ScanSettingsOut,
)
from ..services.settings import scan_settings, update_scan_settings
from .deps import Services, get_services

router = APIRouter(tags=["system"])

ServicesDep = Annotated[Services, Depends(get_services)]


@router.get("/api/health", response_model=HealthOut)
def health(services: ServicesDep) -> dict:
    """Liveness plus the facts the UI needs to render its header."""
    return {
        "status": "ok",
        "version": __version__,
        "database": services.settings.db_path.name,
        "ai_configured": services.ai.config().enabled,
        "repositories": services.store.count_repositories(),
        "scans": services.store.count_scans(),
    }


@router.get("/api/profiles")
def profiles() -> list[dict]:
    """The available scan profiles and exactly what each one changes."""
    return list_profiles()


@router.get("/api/settings/scan", response_model=ScanSettingsOut)
def read_scan_settings(services: ServicesDep) -> dict:
    return scan_settings(services.store, services.settings)


@router.put("/api/settings/scan", response_model=ScanSettingsOut)
def write_scan_settings(payload: ScanSettingsIn, services: ServicesDep) -> dict:
    return update_scan_settings(services.store, payload)


@router.get("/api/settings/ai", response_model=AISettingsOut)
def read_ai_settings(services: ServicesDep) -> dict:
    """The AI configuration. The API key itself is never returned."""
    return services.ai.settings_view()


@router.put("/api/settings/ai", response_model=AISettingsOut)
def write_ai_settings(payload: AISettingsIn, services: ServicesDep) -> dict:
    return services.ai.update_settings(payload)


@router.post("/api/settings/ai/test", response_model=AIConnectionTestOut)
def test_ai_connection(services: ServicesDep) -> dict:
    return services.ai.test_connection()
