"""Verify which allow-listed tools are actually available on this worker."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .registry import TOOL_ORDER, TOOLS, ToolSpec

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def _binary_path(spec: ToolSpec) -> str | None:
    candidate = os.environ.get(spec.env_binary, "").strip() if spec.env_binary else ""
    candidate = candidate or spec.binary or ""
    if os.path.isabs(candidate):
        return candidate if os.path.isfile(candidate) and os.access(candidate, os.X_OK) else None
    return shutil.which(candidate)


def _verify_binary(spec: ToolSpec) -> dict:
    executable = _binary_path(spec)
    base = {"key": spec.key, "name": spec.name, "installed": False, "version": None}
    if not executable:
        return {**base, "status": "unavailable", "detail": "Executable was not found or is not executable."}
    try:
        result = subprocess.run(
            [executable, *spec.version_args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=5,
            check=False,
            shell=False,
            close_fds=True,
        )
    except (OSError, subprocess.SubprocessError):
        return {**base, "status": "unavailable", "detail": "Version check failed."}
    output = _ANSI_ESCAPE.sub("", result.stdout[:4096].decode("utf-8", "replace")).strip()
    if result.returncode != 0 or not output:
        return {**base, "status": "unavailable", "detail": "Executable did not report a version."}
    version_lines = (
        line.strip()
        for line in output.splitlines()
        if line.strip() and not re.fullmatch(r"[#=*_-]{3,}", line.strip())
    )
    version = next(version_lines, "")[:250]
    return {
        **base,
        "installed": True,
        "status": "available",
        "version": version,
        "executable": executable,
        "detail": None,
    }


def _verify_service(spec: ToolSpec) -> dict:
    base = {"key": spec.key, "name": spec.name, "installed": False, "version": None}
    configured_url = os.environ.get(spec.service_env or "", "").strip().rstrip("/")
    if not configured_url:
        return {**base, "status": "unavailable", "detail": "Service endpoint is not configured."}
    parsed = urlsplit(configured_url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        return {**base, "status": "unavailable", "detail": "Service endpoint configuration is invalid."}
    endpoint = f"{configured_url}/JSON/core/view/version/"
    headers = {"Accept": "application/json"}
    api_key = os.environ.get("ZAP_API_KEY", "").strip()
    if api_key:
        headers["X-ZAP-API-Key"] = api_key
    request = Request(endpoint, headers=headers)
    try:
        with build_opener(_NoRedirect()).open(request, timeout=3) as response:
            import json

            payload = json.loads(response.read(16_384).decode("utf-8", "replace"))
    except (HTTPError, URLError, OSError, ValueError):
        return {**base, "status": "unavailable", "detail": "Configured service did not return a valid version."}
    version = payload.get("version") if isinstance(payload, dict) else None
    if not isinstance(version, str) or not version.strip():
        return {**base, "status": "unavailable", "detail": "Configured service did not report a version."}
    return {**base, "installed": True, "status": "available", "version": version[:250], "detail": None}


def tool_inventory() -> list[dict]:
    """Return a fresh, verified inventory; never infer installed state."""
    result = []
    for key in TOOL_ORDER:
        spec = TOOLS[key]
        result.append(_verify_service(spec) if spec.kind == "service" else _verify_binary(spec))
    return result


def inventory_map() -> dict[str, dict]:
    return {row["key"]: row for row in tool_inventory()}


__all__ = ["inventory_map", "tool_inventory"]
