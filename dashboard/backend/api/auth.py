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


def _request_is_https(request: Request) -> bool:
    """True when the browser reached us over HTTPS.

    The Cloudflare tunnel terminates TLS and forwards over http, so trust the
    ``X-Forwarded-Proto`` it sets; a direct localhost request is plain http.
    """
    forwarded = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return forwarded == "https" or request.url.scheme == "https"


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
def login(payload: LoginIn, request: Request, response: Response) -> dict:
    credential = auth_credential()
    if not credential:
        return {"auth_required": False, "authenticated": True}
    supplied = f"{payload.username}:{payload.password}".encode("utf-8")
    if not hmac.compare_digest(supplied, credential.encode("utf-8")):
        response.status_code = 401
        return {"auth_required": True, "authenticated": False}
    # HttpOnly always; SameSite=Lax; Secure only when actually served over HTTPS
    # (the tunnel) so the cookie still works on plain-http localhost.
    secure = _request_is_https(request)
    response.set_cookie(COOKIE_NAME, make_token(credential), max_age=SESSION_TTL, httponly=True, samesite="lax", secure=secure, path="/")
    return {"auth_required": True, "authenticated": True}


@router.post("/api/auth/logout", response_model=AuthStatusOut)
def logout(request: Request, response: Response) -> dict:
    secure = _request_is_https(request)
    response.delete_cookie(COOKIE_NAME, path="/", httponly=True, samesite="lax", secure=secure)
    return {"auth_required": bool(auth_credential()), "authenticated": False}
