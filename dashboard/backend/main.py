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
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__
from .ai.provider import AIError
from .api import ai, dashboard, findings, intel, repositories, scans, system
from .api.deps import build_services
from .config import Settings, get_settings
from .security import ValidationError, safe_error


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

    for module in (system, dashboard, repositories, scans, findings, ai, intel):
        app.include_router(module.router)

    return app


def main() -> None:
    import uvicorn

    settings = get_settings()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, log_level="info")


if __name__ == "__main__":
    main()
