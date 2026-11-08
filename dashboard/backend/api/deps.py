"""Shared service container exposed to the API through a FastAPI dependency.

The container is created once per application instance and stored on
``app.state``, so every route sees the same SQLite store, scan runner and AI
service. This keeps the routes thin and makes the wiring testable.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request

from ..ai.service import AIService
from ..config import Settings, get_settings
from ..persistence.database import Database
from ..persistence.store import Store
from ..services.dashboard import DashboardService
from ..services.repositories import RepositoryService
from ..services.scans import ScanRunner


@dataclass
class Services:
    settings: Settings
    database: Database
    store: Store
    repositories: RepositoryService
    scans: ScanRunner
    dashboard: DashboardService
    ai: AIService


def build_services(settings: Settings | None = None) -> Services:
    resolved = settings or get_settings()
    database = Database(resolved.db_path)
    store = Store(database)
    repositories = RepositoryService(store, resolved)
    return Services(
        settings=resolved,
        database=database,
        store=store,
        repositories=repositories,
        scans=ScanRunner(store, resolved, repositories),
        dashboard=DashboardService(store, resolved),
        ai=AIService(store, resolved),
    )


def get_services(request: Request) -> Services:
    return request.app.state.services
