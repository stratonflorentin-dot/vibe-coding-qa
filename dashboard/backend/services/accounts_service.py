"""Authentication and account management for a self-hosted installation.

This ties the pure :mod:`dashboard.backend.accounts` helpers to the database.
It supports three modes, so upgrading an existing install never locks anyone
out:

* ``open``       - no users and no ``VCQA_BASIC_AUTH``: localhost, unauthenticated.
* ``credential`` - the legacy single ``VCQA_BASIC_AUTH`` and no users yet.
* ``accounts``   - at least one user exists: real accounts, roles and sessions.

Creating the first owner (``setup_owner``) moves an install into ``accounts``
mode. Sessions are server-side and revocable; logins are rate-limited; every
sensitive action is written to the audit log.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..accounts import (
    Role,
    SESSION_TTL_SECONDS,
    hash_password,
    new_session_token,
    session_token_hash,
    validate_password,
    validate_username,
    verify_password,
)
from ..config import Settings
from ..persistence.database import utcnow
from ..persistence.store import Store
from ..security import RateLimiter, ValidationError
from ..sessions import auth_credential


class AccountError(ValidationError):
    """A rejected account operation (bad input, policy or state conflict)."""


class RateLimited(Exception):
    """Raised when login attempts exceed the allowed rate."""

    def __init__(self, message: str = "Too many attempts; try again shortly."):
        super().__init__(message)
        self.message = message


class AccountService:
    def __init__(self, store: Store, settings: Settings):
        self.store = store
        self.settings = settings
        # Deliberately strict: 10 failed-or-successful attempts per 5 minutes,
        # keyed by username+IP, slows credential stuffing without locking a
        # legitimate user out for long.
        self.login_limiter = RateLimiter(max_requests=10, window_seconds=300.0)

    # --------------------------------------------------------------- mode
    def mode(self) -> str:
        if self.store.count_users() > 0:
            return "accounts"
        if auth_credential():
            return "credential"
        return "open"

    def auth_required(self) -> bool:
        return self.mode() != "open"

    def needs_setup(self) -> bool:
        """True when accounts are not yet configured (no users exist)."""
        return self.store.count_users() == 0

    # ------------------------------------------------------- user management
    def _public(self, user: dict | None) -> dict | None:
        if not user:
            return None
        return {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "is_active": bool(user["is_active"]),
            "created_at": user.get("created_at"),
            "last_login_at": user.get("last_login_at"),
        }

    def list_users(self) -> list[dict]:
        return [self._public(u) for u in self.store.list_users()]

    def _insert(self, username: str, password: str, role: Role) -> dict:
        name = validate_username(username)
        validate_password(password)
        if self.store.get_user_by_username(name):
            raise AccountError("That username is already taken.")
        return self.store.create_user(username=name, password_hash=hash_password(password), role=role.slug)

    def setup_owner(self, username: str, password: str, *, ip: str | None = None) -> dict:
        if self.store.count_users() > 0:
            raise AccountError("Setup has already been completed.")
        user = self._insert(username, password, Role.OWNER)
        self.store.add_audit(action="setup.owner", user_id=user["id"], username=user["username"], ip=ip)
        return self._public(user)

    def create_user(self, *, actor: dict, username: str, password: str, role, ip: str | None = None) -> dict:
        role = Role.parse(role)
        user = self._insert(username, password, role)
        self.store.add_audit(
            action="user.create", user_id=actor["id"], username=actor["username"],
            target=user["username"], detail=role.slug, ip=ip,
        )
        return self._public(user)

    def set_role(self, *, actor: dict, user_id: int, role, ip: str | None = None) -> dict:
        role = Role.parse(role)
        target = self.store.get_user(user_id)
        if not target:
            raise AccountError("User not found.")
        if target["role"] == Role.OWNER.slug and role != Role.OWNER and self.store.count_active_owners(exclude_user_id=user_id) == 0:
            raise AccountError("The last owner cannot be demoted.")
        self.store.update_user(user_id, role=role.slug)
        self.store.add_audit(
            action="user.role", user_id=actor["id"], username=actor["username"],
            target=target["username"], detail=role.slug, ip=ip,
        )
        return self._public(self.store.get_user(user_id))

    def set_active(self, *, actor: dict, user_id: int, is_active: bool, ip: str | None = None) -> dict:
        target = self.store.get_user(user_id)
        if not target:
            raise AccountError("User not found.")
        if not is_active and target["role"] == Role.OWNER.slug and self.store.count_active_owners(exclude_user_id=user_id) == 0:
            raise AccountError("The last owner cannot be deactivated.")
        self.store.update_user(user_id, is_active=is_active)
        if not is_active:
            self.store.revoke_user_sessions(user_id)
        self.store.add_audit(
            action="user.active", user_id=actor["id"], username=actor["username"],
            target=target["username"], detail="active" if is_active else "inactive", ip=ip,
        )
        return self._public(self.store.get_user(user_id))

    def set_password(self, *, actor: dict, user_id: int, password: str, ip: str | None = None) -> dict:
        validate_password(password)
        target = self.store.get_user(user_id)
        if not target:
            raise AccountError("User not found.")
        self.store.update_user(user_id, password_hash=hash_password(password))
        # A password change invalidates existing sessions for that user.
        self.store.revoke_user_sessions(user_id)
        self.store.add_audit(
            action="user.password", user_id=actor["id"], username=actor["username"],
            target=target["username"], ip=ip,
        )
        return self._public(self.store.get_user(user_id))

    def delete_user(self, *, actor: dict, user_id: int, ip: str | None = None) -> None:
        target = self.store.get_user(user_id)
        if not target:
            raise AccountError("User not found.")
        if actor["id"] == user_id:
            raise AccountError("You cannot remove your own account.")
        if target["role"] == Role.OWNER.slug and self.store.count_active_owners(exclude_user_id=user_id) == 0:
            raise AccountError("The last owner cannot be removed.")
        self.store.delete_user(user_id)
        self.store.add_audit(
            action="user.delete", user_id=actor["id"], username=actor["username"],
            target=target["username"], ip=ip,
        )

    # ----------------------------------------------------------- authentication
    def authenticate(self, username: str, password: str, *, ip: str | None = None) -> dict | None:
        key = f"{(username or '').lower()}|{ip or '-'}"
        if not self.login_limiter.allow(key):
            raise RateLimited("Too many login attempts. Wait a few minutes and try again.")
        user = self.store.get_user_by_username(username or "")
        ok = bool(user) and bool(user["is_active"]) and verify_password(password or "", user["password_hash"])
        self.store.add_audit(
            action="login.success" if ok else "login.failure",
            user_id=user["id"] if user else None, username=username or None, ip=ip,
        )
        if not ok:
            return None
        self.store.update_user(user["id"], last_login_at=utcnow())
        return user

    def start_session(self, user: dict, *, ip: str | None = None, user_agent: str | None = None) -> str:
        token = new_session_token()
        expires = (datetime.now(timezone.utc) + timedelta(seconds=SESSION_TTL_SECONDS)).isoformat(timespec="seconds")
        self.store.create_session(
            user_id=user["id"], token_hash=session_token_hash(token),
            expires_at=expires, ip=ip, user_agent=(user_agent or "")[:400] or None,
        )
        return token

    def resolve_session(self, token: str | None) -> dict | None:
        """Return the live user for a session token, or ``None`` if not valid."""
        if not token:
            return None
        row = self.store.get_session_with_user(session_token_hash(token))
        if not row or row["revoked_at"] or not row["is_active"]:
            return None
        try:
            expires = datetime.fromisoformat(row["expires_at"])
        except (TypeError, ValueError):
            return None
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < datetime.now(timezone.utc):
            return None
        return {"id": row["user_id"], "username": row["username"], "role": row["role"]}

    def revoke_session(self, token: str | None) -> bool:
        if not token:
            return False
        return self.store.revoke_session(session_token_hash(token))

    def recent_audit(self, limit: int = 100) -> list[dict]:
        return self.store.list_audit(limit=limit)
