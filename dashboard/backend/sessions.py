"""Signed session tokens for the dashboard's form-based login.

The dashboard protects a tunnelled/public deployment with a single operator
credential (``VCQA_BASIC_AUTH`` = ``user:password``). Instead of HTTP Basic Auth
- which makes the browser pop its own native sign-in dialog - the API accepts a
signed session cookie issued by ``POST /api/auth/login``. The token is an HMAC
over an expiry timestamp, keyed by a secret derived from the credential, so it
needs no extra configuration and is invalidated automatically if the password
changes. HTTP Basic is still accepted for CLI/``curl`` callers.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import time

COOKIE_NAME = "vcqa_session"
SESSION_TTL = 7 * 24 * 3600  # 7 days


def auth_credential() -> str:
    """The configured ``user:password`` credential, or ``""`` when auth is off."""
    return os.environ.get("VCQA_BASIC_AUTH", "").strip()


def _secret(credential: str) -> bytes:
    return hashlib.sha256(("vcqa-session-v1:" + credential).encode("utf-8")).digest()


def make_token(credential: str, ttl: int = SESSION_TTL) -> str:
    exp = int(time.time()) + ttl
    sig = hmac.new(_secret(credential), str(exp).encode("ascii"), hashlib.sha256).hexdigest()
    return f"{exp}.{sig}"


def valid_token(credential: str, token: str | None) -> bool:
    if not credential or not token:
        return False
    try:
        exp_str, sig = token.split(".", 1)
        exp = int(exp_str)
    except (ValueError, AttributeError):
        return False
    if exp < time.time():
        return False
    expected = hmac.new(_secret(credential), str(exp).encode("ascii"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)


def check_basic(credential: str, authorization: bytes | str | None) -> bool:
    """Accept a legacy HTTP Basic header (for the CLI / curl)."""
    if not credential or not authorization:
        return False
    raw = authorization if isinstance(authorization, bytes) else str(authorization).encode("utf-8")
    if raw[:6].lower() != b"basic ":
        return False
    token = raw[6:].strip()
    try:
        supplied = base64.b64decode(token + b"=" * (-len(token) % 4))
    except (binascii.Error, ValueError):
        return False
    return hmac.compare_digest(supplied, credential.encode("utf-8"))


def cookie_value(cookie_header: str, name: str) -> str | None:
    """Pull a single cookie value out of a raw ``Cookie:`` header."""
    for part in (cookie_header or "").split(";"):
        key, sep, value = part.strip().partition("=")
        if sep and key == name:
            return value
    return None
