"""Optional, read-only PentAGI integration.

PentAGI is an external autonomous-pentest platform. This integration is
deliberately limited to a **read-only availability probe**: when an operator has
configured ``PENTAGI_BASE_URL`` and ``PENTAGI_API_TOKEN``, a live-target scan can
confirm the platform is reachable by issuing exactly one ``GET /api/v1/flows``.
It never launches a flow, never authenticates to the target, and never attacks
anything - matching the project's read-only, least-surprise posture.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
_MAX_TIMEOUT = 15.0


class PentagiError(ValueError):
    """Raised when the PentAGI configuration is invalid."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):  # noqa: D102
        return None


def _flows_endpoint(base_url: str) -> str:
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise PentagiError("PentAGI base URL must be an absolute HTTP(S) URL.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise PentagiError(
            "PentAGI base URL cannot contain credentials, query parameters, or a fragment."
        )
    if parsed.scheme != "https" and parsed.hostname.lower() not in _LOCAL_HOSTS:
        raise PentagiError("Non-local PentAGI endpoints must use HTTPS.")
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}/api/v1/flows"


@dataclass(frozen=True)
class PentagiConfig:
    base_url: str
    token: str

    @classmethod
    def from_env(cls, env: dict | None = None) -> "PentagiConfig | None":
        values = os.environ if env is None else env
        base = (values.get("PENTAGI_BASE_URL") or "").strip()
        token = (values.get("PENTAGI_API_TOKEN") or "").strip()
        if not base or not token:
            return None
        return cls(base_url=base, token=token)


def configured(env: dict | None = None) -> bool:
    """Whether a PentAGI base URL and token are both present."""
    return PentagiConfig.from_env(env) is not None


def probe(config: PentagiConfig | None = None, *, timeout: float = 10.0) -> dict:
    """Issue exactly one read-only ``GET /api/v1/flows``. Never starts a flow.

    The token is only ever sent as a request header and is never returned.
    """
    config = config or PentagiConfig.from_env()
    if config is None:
        return {"configured": False, "reachable": False, "detail": "PentAGI is not configured."}
    try:
        endpoint = _flows_endpoint(config.base_url)
    except PentagiError as exc:
        return {"configured": True, "reachable": False, "detail": str(exc)}

    request = Request(
        endpoint,
        method="GET",
        headers={"Authorization": f"Bearer {config.token}", "Accept": "application/json"},
    )
    try:
        with build_opener(_NoRedirect()).open(request, timeout=min(timeout, _MAX_TIMEOUT)) as response:
            status = int(response.status)
    except HTTPError as exc:
        status = int(exc.code)
    except (URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        return {
            "configured": True,
            "reachable": False,
            "endpoint": endpoint,
            "detail": f"The PentAGI status request failed: {reason}",
        }
    return {
        "configured": True,
        "reachable": 200 <= status < 300,
        "http_status": status,
        "endpoint": endpoint,
        "operation": "GET /api/v1/flows",
    }


__all__ = ["PentagiConfig", "PentagiError", "configured", "probe"]
