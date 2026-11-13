"""Shared service container exposed to the API through a FastAPI dependency.

The container is created once per application instance and stored on
``app.state``, so every route sees the same SQLite store, scan runner and AI
service. This keeps the routes thin and makes the wiring testable.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException, Request

from ..accounts import Role, role_at_least
from ..ai.service import AIService
from ..config import Settings, get_settings
from ..intelligence.gateway import IntelligenceGateway
from ..persistence.database import Database
from ..persistence.store import Store
from ..services.accounts_service import AccountService
from ..services.dashboard import DashboardService
from ..services.repositories import RepositoryService
from ..services.security_lab import SecurityLabService
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
    accounts: AccountService
    security_lab: SecurityLabService
    intelligence: IntelligenceGateway


def build_services(settings: Settings | None = None) -> Services:
    resolved = settings or get_settings()
    database = Database(resolved.db_path)
    store = Store(database)
    repositories = RepositoryService(store, resolved)
    ai = AIService(store, resolved)
    return Services(
        settings=resolved,
        database=database,
        store=store,
        repositories=repositories,
        scans=ScanRunner(store, resolved, repositories),
        dashboard=DashboardService(store, resolved),
        ai=ai,
        accounts=AccountService(store, resolved),
        security_lab=SecurityLabService(store, max_concurrency=resolved.max_concurrent_scans),
        intelligence=IntelligenceGateway(store, ai, resolved),
    )


def get_services(request: Request) -> Services:
    return request.app.state.services


# --------------------------------------------------------------- auth helpers
#: Identity used in non-account modes (localhost-open or the legacy single
#: credential). A single operator holds full authority; audit entries record it
#: as "(operator)" so legacy actions are still attributable.
_LEGACY_OPERATOR = {"id": 0, "username": "(operator)", "role": Role.OWNER.slug, "legacy": True}


def client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip() or None
    return request.client.host if request.client else None


def current_user(request: Request) -> dict | None:
    """Resolve the signed-in account from the session cookie, or ``None``."""
    from ..sessions import COOKIE_NAME

    services = get_services(request)
    if services.accounts.mode() != "accounts":
        return None
    return services.accounts.resolve_session(request.cookies.get(COOKIE_NAME))


def require_authenticated(request: Request) -> dict:
    """Require a signed-in user in account mode; allow the operator otherwise.

    The ASGI auth middleware has already rejected anonymous requests to the data
    API, so reaching here in a non-account mode means the single operator is
    authenticated by the legacy credential (or the install is localhost-open).
    """
    services = get_services(request)
    if services.accounts.mode() != "accounts":
        return dict(_LEGACY_OPERATOR)
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


def require_role(minimum: "str | int | Role"):
    """Dependency factory: require at least ``minimum`` role (RBAC)."""
    required = Role.parse(minimum)

    def dependency(request: Request) -> dict:
        user = require_authenticated(request)
        if not role_at_least(user["role"], required):
            raise HTTPException(
                status_code=403,
                detail="You do not have permission to perform this action.",
            )
        return user

    return dependency


#: Semantic role gates for data routes. Read endpoints are already covered by
#: the auth middleware (any authenticated user = viewer); these guard mutations.
#: In open / legacy-credential mode they resolve to the single operator.
require_viewer = require_role(Role.VIEWER)
require_analyst = require_role(Role.SECURITY_ANALYST)
require_admin = require_role(Role.ADMINISTRATOR)


def require_account_admin(request: Request) -> dict:
    """Require a real administrator account (user management).

    Unlike :func:`require_role`, this refuses the synthetic legacy operator: user
    administration only exists once the install is in account mode.
    """
    services = get_services(request)
    if services.accounts.mode() != "accounts":
        raise HTTPException(status_code=409, detail="Create the first owner account first (setup).")
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    if not role_at_least(user["role"], Role.ADMINISTRATOR):
        raise HTTPException(status_code=403, detail="Administrator role required.")
    return user
