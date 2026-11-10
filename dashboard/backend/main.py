"""FastAPI application factory for the Vibe Coding QA dashboard.

Run it with ``python -m dashboard.backend`` (or
``uvicorn dashboard.backend.main:create_app --factory``).

Security posture:
* bound to localhost by default;
* CORS restricted to the configured local origins;
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
from .api import ai, auth, dashboard, findings, intel, repositories, scans, system
from .api.deps import build_services
from .config import Settings, get_settings
from .security import ValidationError, safe_error
from .sessions import COOKIE_NAME, check_basic, cookie_value, valid_token


class SessionAuthMiddleware:
    """Session-cookie auth gate for a tunnelled/public deployment.

    Inert unless ``VCQA_BASIC_AUTH`` is set (``user:password``). It gates the
    data API (``/api/*`` except ``/api/auth/*``) behind a signed session cookie,
    or an HTTP Basic header for the CLI. Crucially it returns a plain JSON 401
    **without** a ``WWW-Authenticate`` header, so the browser never shows its
    native Basic-Auth popup - the SPA renders its own login screen instead. The
    SPA's static assets are always served so that login screen can load. Pure
    ASGI so SSE streaming responses are never buffered.
    """

    def __init__(self, app, *, credential: str):
        self.app = app
        self.credential = credential

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
        headers = dict(scope.get("headers") or [])
        token = cookie_value(headers.get(b"cookie", b"").decode("latin-1"), COOKIE_NAME)
        if valid_token(self.credential, token) or check_basic(self.credential, headers.get(b"authorization", b"")):
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
        try:
            yield
        finally:
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

    # Added last on purpose: Starlette applies the most recently added middleware
    # outermost, so the auth gate protects every route (and CORS preflight).
    basic_auth = os.environ.get("VCQA_BASIC_AUTH", "").strip()
    if basic_auth:
        app.add_middleware(SessionAuthMiddleware, credential=basic_auth)

    @app.exception_handler(ValidationError)
    async def _validation_error(_: Request, exc: ValidationError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc), "code": "validation_error"})

    @app.exception_handler(AIError)
    async def _ai_error(_: Request, exc: AIError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc), "code": "ai_error"})

    @app.exception_handler(KeyError)
    async def _not_found(_: Request, exc: KeyError) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={"detail": safe_error(exc, "The requested item was not found."), "code": "not_found"},
        )

    for module in (system, auth, dashboard, repositories, scans, findings, ai, intel):
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
