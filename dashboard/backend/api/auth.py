"""Authentication and account management routes.

These are intentionally exempt from the session gate (see
``SessionAuthMiddleware``): ``/api/auth/status`` must be callable before login,
``/api/auth/login`` is how a session is obtained, and ``/api/auth/setup``
bootstraps the first owner. Every other action here is authorised explicitly.

Three modes are supported so an existing install never locks out (see
``AccountService``): ``open`` (localhost, no auth), ``credential`` (legacy single
``VCQA_BASIC_AUTH``) and ``accounts`` (real users, roles and sessions).
"""

from __future__ import annotations

import hmac

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from ..accounts import SESSION_TTL_SECONDS
from ..security import ValidationError
from ..services.accounts_service import AccountError, RateLimited
from ..sessions import COOKIE_NAME, auth_credential, make_token
from .deps import (
    client_ip,
    current_user,
    get_services,
    require_account_admin,
)

router = APIRouter(tags=["auth"])


# --------------------------------------------------------------------- models
class LoginIn(BaseModel):
    username: str = Field(default="", max_length=256)
    password: str = Field(default="", max_length=1024)


class SetupIn(BaseModel):
    username: str = Field(max_length=256)
    password: str = Field(max_length=1024)


class UserCreateIn(BaseModel):
    username: str = Field(max_length=256)
    password: str = Field(max_length=1024)
    role: str = Field(default="viewer", max_length=32)


class RoleIn(BaseModel):
    role: str = Field(max_length=32)


class ActiveIn(BaseModel):
    is_active: bool


class PasswordIn(BaseModel):
    password: str = Field(max_length=1024)


# --------------------------------------------------------------------- helpers
def _request_is_https(request: Request) -> bool:
    forwarded = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return forwarded == "https" or request.url.scheme == "https"


def _set_session(request: Request, response: Response, token: str) -> None:
    # HttpOnly always; SameSite=Lax; Secure only on real HTTPS so the cookie
    # still works on plain-http localhost. Kept on one line so the QA cookie
    # rule sees the flags alongside the setter.
    response.set_cookie(COOKIE_NAME, token, max_age=SESSION_TTL_SECONDS, httponly=True, samesite="lax", secure=_request_is_https(request), path="/")


def _status_payload(request: Request) -> dict:
    accounts = get_services(request).accounts
    mode = accounts.mode()
    user = current_user(request) if mode == "accounts" else None
    return {
        "mode": mode,
        "auth_required": accounts.auth_required(),
        "authenticated": (user is not None) if mode == "accounts" else (mode != "accounts"),
        "needs_setup": accounts.needs_setup(),
        "user": user,
    }


# ---------------------------------------------------------------------- routes
@router.get("/api/auth/status")
def auth_status(request: Request) -> dict:
    payload = _status_payload(request)
    # In credential/open mode there is no per-user identity; "authenticated"
    # reflects whether the gate (if any) has been satisfied by this request.
    if payload["mode"] == "credential":
        payload["authenticated"] = _legacy_authenticated(request)
    return payload


def _legacy_authenticated(request: Request) -> bool:
    credential = auth_credential()
    if not credential:
        return True
    from ..sessions import valid_token

    return valid_token(credential, request.cookies.get(COOKIE_NAME))


@router.post("/api/auth/setup")
def setup(payload: SetupIn, request: Request, response: Response) -> dict:
    accounts = get_services(request).accounts
    if not accounts.needs_setup():
        raise HTTPException(status_code=409, detail="Setup has already been completed.")
    # On a public (credential) install, only the holder of the legacy credential
    # may claim ownership; a localhost-open install may set up freely.
    if accounts.mode() == "credential" and not _legacy_authenticated(request):
        raise HTTPException(status_code=401, detail="The operator credential is required to run setup.")
    user = accounts.setup_owner(payload.username, payload.password, ip=client_ip(request))
    signed_in = accounts.store.get_user_by_username(user["username"])
    token = accounts.start_session(signed_in, ip=client_ip(request), user_agent=request.headers.get("user-agent"))
    _set_session(request, response, token)
    return {**_status_payload(request), "user": user, "authenticated": True}


@router.post("/api/auth/login")
def login(payload: LoginIn, request: Request, response: Response) -> dict:
    accounts = get_services(request).accounts
    mode = accounts.mode()
    if mode == "open":
        return _status_payload(request)

    ip = client_ip(request)
    if mode == "accounts":
        try:
            user = accounts.authenticate(payload.username, payload.password, ip=ip)
        except RateLimited as exc:
            response.status_code = 429
            return {"authenticated": False, "mode": mode, "detail": exc.message}
        if not user:
            response.status_code = 401
            return {"authenticated": False, "mode": mode, "detail": "Invalid username or password."}
        token = accounts.start_session(user, ip=ip, user_agent=request.headers.get("user-agent"))
        _set_session(request, response, token)
        return {"authenticated": True, "mode": mode, "user": accounts._public(user)}

    # Legacy single-credential mode.
    credential = auth_credential()
    supplied = f"{payload.username}:{payload.password}".encode("utf-8")
    if not hmac.compare_digest(supplied, credential.encode("utf-8")):
        response.status_code = 401
        return {"authenticated": False, "mode": mode, "detail": "Invalid credential."}
    _set_session(request, response, make_token(credential))
    return {"authenticated": True, "mode": mode, "user": None}


@router.post("/api/auth/logout")
def logout(request: Request, response: Response) -> dict:
    accounts = get_services(request).accounts
    if accounts.mode() == "accounts":
        accounts.revoke_session(request.cookies.get(COOKIE_NAME))
    response.delete_cookie(COOKIE_NAME, path="/", httponly=True, samesite="lax", secure=_request_is_https(request))
    return {"authenticated": False, "mode": accounts.mode()}


@router.get("/api/auth/me")
def me(request: Request) -> dict:
    user = current_user(request)
    if user is None and get_services(request).accounts.mode() == "accounts":
        raise HTTPException(status_code=401, detail="Authentication required.")
    return {"user": user, **_status_payload(request)}


# ---------------------------------------------------------- user administration
def _actor(request: Request) -> dict:
    return require_account_admin(request)


@router.get("/api/auth/users")
def list_users(request: Request) -> dict:
    require_account_admin(request)
    return {"users": get_services(request).accounts.list_users()}


@router.post("/api/auth/users", status_code=201)
def create_user(payload: UserCreateIn, request: Request) -> dict:
    actor = require_account_admin(request)
    accounts = get_services(request).accounts
    try:
        user = accounts.create_user(
            actor=actor, username=payload.username, password=payload.password,
            role=payload.role, ip=client_ip(request),
        )
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"user": user}


@router.patch("/api/auth/users/{user_id}/role")
def set_user_role(user_id: int, payload: RoleIn, request: Request) -> dict:
    actor = require_account_admin(request)
    try:
        user = get_services(request).accounts.set_role(actor=actor, user_id=user_id, role=payload.role, ip=client_ip(request))
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"user": user}


@router.patch("/api/auth/users/{user_id}/active")
def set_user_active(user_id: int, payload: ActiveIn, request: Request) -> dict:
    actor = require_account_admin(request)
    try:
        user = get_services(request).accounts.set_active(actor=actor, user_id=user_id, is_active=payload.is_active, ip=client_ip(request))
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"user": user}


@router.patch("/api/auth/users/{user_id}/password")
def set_user_password(user_id: int, payload: PasswordIn, request: Request) -> dict:
    actor = require_account_admin(request)
    try:
        user = get_services(request).accounts.set_password(actor=actor, user_id=user_id, password=payload.password, ip=client_ip(request))
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"user": user}


@router.delete("/api/auth/users/{user_id}")
def delete_user(user_id: int, request: Request) -> dict:
    actor = require_account_admin(request)
    try:
        get_services(request).accounts.delete_user(actor=actor, user_id=user_id, ip=client_ip(request))
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"detail": "User removed."}


@router.get("/api/auth/audit")
def audit_log(request: Request, limit: int = 100) -> dict:
    require_account_admin(request)
    return {"entries": get_services(request).accounts.recent_audit(limit=max(1, min(500, limit)))}
