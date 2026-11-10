"""Form-based login so the browser never shows its native Basic-Auth popup.

These routes are intentionally exempt from the session gate (see
``SessionAuthMiddleware``): ``/api/auth/status`` must be callable before login so
the SPA can decide whether to show its login screen, and ``/api/auth/login`` is
how you get a session in the first place. When no credential is configured the
dashboard is open (localhost-only) and these report ``auth_required = false``.
"""

from __future__ import annotations

import hmac

from fastapi import APIRouter, Request, Response

from ..schemas import AuthStatusOut, LoginIn
from ..sessions import COOKIE_NAME, SESSION_TTL, auth_credential, make_token, valid_token

router = APIRouter(tags=["auth"])


@router.get("/api/auth/status", response_model=AuthStatusOut)
def auth_status(request: Request) -> dict:
    credential = auth_credential()
    if not credential:
        return {"auth_required": False, "authenticated": True}
    return {
        "auth_required": True,
        "authenticated": valid_token(credential, request.cookies.get(COOKIE_NAME)),
    }


@router.post("/api/auth/login", response_model=AuthStatusOut)
def login(payload: LoginIn, response: Response) -> dict:
    credential = auth_credential()
    if not credential:
        return {"auth_required": False, "authenticated": True}
    supplied = f"{payload.username}:{payload.password}".encode("utf-8")
    if not hmac.compare_digest(supplied, credential.encode("utf-8")):
        response.status_code = 401
        return {"auth_required": True, "authenticated": False}
    # Not marked Secure: the tunnel terminates TLS at Cloudflare and reaches the
    # backend over http, and the cookie must also work on plain-http localhost.
    response.set_cookie(
        COOKIE_NAME,
        make_token(credential),
        max_age=SESSION_TTL,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return {"auth_required": True, "authenticated": True}


@router.post("/api/auth/logout", response_model=AuthStatusOut)
def logout(response: Response) -> dict:
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"auth_required": bool(auth_credential()), "authenticated": False}
