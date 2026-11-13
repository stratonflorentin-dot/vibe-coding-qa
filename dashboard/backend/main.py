"""FastAPI application factory for the Vibe Coding QA dashboard.

Run it with ``python -m dashboard.backend`` (or
``uvicorn dashboard.backend.main:create_app --factory``).

Security posture:
* bound to localhost by default;
* CORS restricted to the configured local origins;
* state-changing requests are refused unless they are same-origin (CSRF guard);
* a repository must live inside an allow-listed root to be registered;
* the AI provider key stays on the server and is never returned;
* the release gate is computed by the engine, never by the API or the AI layer.
"""

from __future__ import annotations

import ipaddress
import os
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__
from .ai.provider import AIError
from .api import ai, auth, dashboard, findings, intel, intelligence, repositories, scans, security, system
from .api.deps import build_services
from .config import Settings, get_settings
from .security import ValidationError, safe_error
from .accounts import PasswordPolicyError
from .intelligence.exceptions import IntelligenceError
from .sessions import COOKIE_NAME, auth_credential, check_basic, cookie_value, valid_token


class SessionAuthMiddleware:
    """Session gate for account mode and the legacy single credential.

    Inert in ``open`` mode (localhost, no users, no credential). In ``accounts``
    mode it requires a valid server-side session cookie; the legacy
    ``VCQA_BASIC_AUTH`` (cookie HMAC or an HTTP Basic header for the CLI) is also
    accepted. It returns a plain JSON 401 **without** a ``WWW-Authenticate``
    header, so the browser never shows its native popup - the SPA renders its own
    login screen. The SPA's static assets and ``/api/auth/*`` are always served
    so login can proceed. Pure ASGI so SSE responses are never buffered.
    """

    def __init__(self, app, *, services):
        self.app = app
        self.services = services

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "") or ""
        method = scope.get("method", "GET")
        # Let the SPA, the auth endpoints, and CORS preflight through unguarded.
        if method == "OPTIONS" or not path.startswith("/api/") or path.startswith("/api/auth/"):
            await self.app(scope, receive, send)
            return

        accounts = self.services.accounts
        mode = accounts.mode()
        if mode == "open":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        cookie_header = headers.get(b"cookie", b"").decode("latin-1")
        token = cookie_value(cookie_header, COOKIE_NAME)

        authorised = mode == "accounts" and accounts.resolve_session(token) is not None
        if not authorised:
            credential = auth_credential()
            if credential and (valid_token(credential, token) or check_basic(credential, headers.get(b"authorization", b""))):
                authorised = True

        if authorised:
            await self.app(scope, receive, send)
            return

        body = b'{"detail":"Authentication required.","code":"auth_required"}'
        await send({
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": body})


#: Methods that can change state; only these need a CSRF check.
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class SameOriginGuard:
    """Reject cross-site state-changing requests (CSRF, defence in depth).

    The session cookie is already ``SameSite=Lax``; this adds an explicit
    same-origin check so a mutation is only accepted when the browser states it
    came from the dashboard itself. Requests that carry no ``Origin``/``Referer``
    (the CLI, ``curl``, the SSE stream) are left untouched: they hold no ambient
    cookie a third-party page could ride on. ``/api/auth/*`` is exempt, matching
    ``SessionAuthMiddleware``, so login/setup can never be locked out by a proxy
    that rewrites ``Host``.
    """

    def __init__(self, app, *, allowed_origins):
        self.app = app
        self.allowed = {origin.rstrip("/").lower() for origin in allowed_origins}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "") or ""
        if (
            scope.get("method", "GET") not in _MUTATING_METHODS
            or not path.startswith("/api/")
            or path.startswith("/api/auth/")
        ):
            await self.app(scope, receive, send)
            return

        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers") or []
        }
        if self._same_origin(headers):
            await self.app(scope, receive, send)
            return

        body = b'{"detail":"Cross-site request rejected.","code":"csrf_rejected"}'
        await send({
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": body})

    def _same_origin(self, headers: dict) -> bool:
        origin = headers.get("origin")
        if origin:
            return self._origin_allowed(origin, headers)
        referer = headers.get("referer")
        if referer:
            return self._origin_allowed(referer, headers)
        return True

    def _origin_allowed(self, value: str, headers: dict) -> bool:
        """True when ``value`` is a configured origin or the request's own host."""
        parsed = urlsplit(value)
        if not parsed.scheme or not parsed.netloc:
            return False  # e.g. "null" - an opaque origin is never trusted
        if f"{parsed.scheme}://{parsed.netloc}".lower() in self.allowed:
            return True
        candidates = set()
        host = headers.get("host")
        if host:
            candidates.add(host.lower())
        forwarded_host = headers.get("x-forwarded-host", "").split(",")[0].strip()
        if forwarded_host:
            candidates.add(forwarded_host.lower())
        return parsed.netloc.lower() in candidates


class _SpaStaticFiles(StaticFiles):
    """Serve the built dashboard and fall back to index.html for client routes."""

    async def get_response(self, path: str, scope):
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code == 404:
                return await super().get_response("index.html", scope)
            raise


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()
    try:
        host_is_loopback = resolved.host.lower() == "localhost" or ipaddress.ip_address(resolved.host).is_loopback
    except ValueError:
        host_is_loopback = False
    if not host_is_loopback:
        raise ValueError("The dashboard API must bind to a loopback host; remote access requires authentication.")
    for origin in resolved.cors_origins:
        parsed_origin = urlsplit(origin)
        try:
            origin_is_loopback = parsed_origin.hostname == "localhost" or ipaddress.ip_address(
                parsed_origin.hostname or ""
            ).is_loopback
        except ValueError:
            origin_is_loopback = False
        if parsed_origin.scheme not in ("http", "https") or not origin_is_loopback:
            raise ValueError("Dashboard CORS origins must be localhost origins.")
    services = build_services(resolved)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        # A scan that was running when the previous process died can never
        # finish; mark it failed so the UI never shows a phantom "running" job.
        services.scans.recover_interrupted()
        services.store.mark_interrupted_security_jobs()
        try:
            yield
        finally:
            services.security_lab.shutdown()
            services.scans.shutdown()
            services.database.close()

    app = FastAPI(
        title="Vibe Coding QA Dashboard API",
        version=__version__,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    app.state.services = services

    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Accept"],
    )

    # Same-origin guard sits inside the auth gate: an unauthenticated request is
    # rejected first, then a cross-site mutation is refused (CSRF). It runs before
    # CORS so plain ``curl``/CLI callers without an Origin header are unaffected.
    app.add_middleware(SameOriginGuard, allowed_origins=resolved.cors_origins)

    # Added last on purpose: Starlette applies the most recently added middleware
    # outermost, so the auth gate protects every route (and CORS preflight). It is
    # inert in "open" mode and active once users exist or a credential is set, so
    # account mode is protected even without VCQA_BASIC_AUTH.
    app.add_middleware(SessionAuthMiddleware, services=services)

    @app.exception_handler(ValidationError)
    async def _validation_error(_: Request, exc: ValidationError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc), "code": "validation_error"})

    @app.exception_handler(PasswordPolicyError)
    async def _password_policy(_: Request, exc: PasswordPolicyError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc), "code": "validation_error"})

    @app.exception_handler(IntelligenceError)
    async def _intelligence_error(_: Request, exc: IntelligenceError) -> JSONResponse:
        return JSONResponse(status_code=exc.http_status, content={"detail": str(exc), "code": exc.code})

    @app.exception_handler(AIError)
    async def _ai_error(_: Request, exc: AIError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc), "code": "ai_error"})

    @app.exception_handler(KeyError)
    async def _not_found(_: Request, exc: KeyError) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={"detail": safe_error(exc, "The requested item was not found."), "code": "not_found"},
        )

    for module in (system, auth, dashboard, repositories, scans, security, findings, ai, intel, intelligence):
        app.include_router(module.router)

    # Serve the built single-page dashboard when present, so one process (and one
    # tunnelled port) exposes both the UI and the API. Mounted after the routers so
    # /api still wins; unknown paths fall back to index.html for client routing.
    dist = Path(__file__).resolve().parents[1] / "frontend" / "dist"
    if dist.is_dir():
        app.mount("/", _SpaStaticFiles(directory=dist, html=True), name="ui")

    return app


def main() -> None:
    import uvicorn

    settings = get_settings()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, log_level="info")


if __name__ == "__main__":
    main()
