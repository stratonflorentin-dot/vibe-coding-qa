"""Account domain: roles, password hashing and session tokens.

Pure, dependency-free helpers so they can be unit-tested without a database or
the web stack. Password hashing uses :func:`hashlib.scrypt` - a memory-hard,
standard-library algorithm - so no third-party crypto dependency is added.

Session tokens are random 256-bit values; only their SHA-256 hash is ever
stored, so a database leak never exposes a usable session token.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import secrets
from enum import IntEnum


class Role(IntEnum):
    """Installation roles, ordered so a higher value implies more authority.

    A single customer installation has multiple authorised users; this is not
    cross-customer multi-tenancy. ``OWNER`` is the first account created during
    setup and can never be removed while it is the last owner.
    """

    VIEWER = 1
    SECURITY_ANALYST = 2
    ADMINISTRATOR = 3
    OWNER = 4

    @classmethod
    def parse(cls, value: "str | int | Role") -> "Role":
        if isinstance(value, Role):
            return value
        if isinstance(value, int):
            return cls(value)
        key = str(value).strip().upper().replace("-", "_").replace(" ", "_")
        try:
            return cls[key]
        except KeyError as exc:
            raise ValueError(f"Unknown role: {value!r}") from exc

    @property
    def slug(self) -> str:
        return self.name.lower()


def role_at_least(role: "str | int | Role", required: "str | int | Role") -> bool:
    """True when ``role`` has at least the authority of ``required``."""
    return Role.parse(role) >= Role.parse(required)


# ----------------------------------------------------------------- passwords
_SCRYPT_N = 2 ** 14   # CPU/memory cost (~16 MiB at r=8)
_SCRYPT_R = 8
_SCRYPT_P = 1
_DKLEN = 32
MIN_PASSWORD_LENGTH = 10
# Allow email addresses as usernames (@ and +), alongside the usual identifier
# characters. Must start alphanumeric and stay 2-63 characters.
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+@-]{1,62}$")


class PasswordPolicyError(ValueError):
    """Raised when a password or username fails the minimum policy."""


def validate_username(username: str) -> str:
    name = (username or "").strip()
    if not _USERNAME_RE.match(name):
        raise PasswordPolicyError(
            "Username must be 2-63 characters using letters, digits or . _ - + @ "
            "(an email address is fine)."
        )
    return name


def validate_password(password: str) -> None:
    if len(password or "") < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")


def hash_password(password: str) -> str:
    """Return a self-describing scrypt hash: ``scrypt$N$r$p$salt$hash`` (base64)."""
    validate_password(password)
    salt = os.urandom(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_DKLEN
    )
    return "$".join([
        "scrypt", str(_SCRYPT_N), str(_SCRYPT_R), str(_SCRYPT_P),
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(derived).decode("ascii"),
    ])


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of ``password`` against a stored scrypt hash."""
    try:
        algo, n, r, p, salt_b64, hash_b64 = (stored or "").split("$")
        if algo != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        derived = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected)
        )
    except (ValueError, binascii.Error):
        return False
    return hmac.compare_digest(derived, expected)


# ------------------------------------------------------------------ sessions
SESSION_TTL_SECONDS = 7 * 24 * 3600


def new_session_token() -> str:
    """A fresh, unguessable session token (the raw value given to the client)."""
    return secrets.token_urlsafe(32)


def session_token_hash(token: str) -> str:
    """The value stored in the database - never the raw token itself."""
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


__all__ = [
    "MIN_PASSWORD_LENGTH",
    "PasswordPolicyError",
    "Role",
    "SESSION_TTL_SECONDS",
    "hash_password",
    "new_session_token",
    "role_at_least",
    "session_token_hash",
    "validate_password",
    "validate_username",
    "verify_password",
]
