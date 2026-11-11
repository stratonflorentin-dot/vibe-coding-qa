"""Allow-listed tool registry and fixed command templates.

The worker is a security boundary: it is the only component that executes a
security tool, and it does so on behalf of a remote API. That makes arbitrary
command execution the single most dangerous thing it could get wrong, so this
module removes the possibility entirely:

* A caller names a **tool key** (``nmap``, ``nuclei``, ...) and supplies a
  *validated* target. It can never supply an executable path, a shell string, or
  a raw argument list.
* Every argument is built here, from a fixed template, out of values that have
  already passed :func:`validate_http_url` / :func:`validate_target_host` /
  :func:`validate_port`.
* Processes are started with ``shell=False`` and an argument *list*, so even a
  value that somehow slipped through could not become a shell metacharacter.

Tools that need an OWASP ZAP daemon are modelled as *service* tools: they are
reached over HTTP rather than launched as a binary, and "installed" means the
daemon answered its version endpoint.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

#: Tools that are intrusive or otherwise higher-impact. They are never part of a
#: default profile and require an explicit, per-job authorisation flag.
GATED_TOOLS: frozenset[str] = frozenset({"sqlmap", "gobuster"})

#: Every tool the worker knows about, in a stable display order.
TOOL_ORDER: tuple[str, ...] = (
    "nmap", "nuclei", "zap", "nikto", "whatweb", "testssl", "sqlmap", "gobuster",
)

_HOST_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


class ToolArgumentError(ValueError):
    """Raised when a tool key, target or argument combination is not allowed."""


# --------------------------------------------------------------------- target IO
def validate_target_host(value: str) -> str:
    """Return a canonical host (DNS name or IP literal), or raise.

    The result is safe to place on a command line: it is either a valid IP
    literal or a DNS name matching a strict pattern, so it can never begin with
    ``-`` (an option-injection attempt) and can never contain a space, quote or
    shell metacharacter.
    """
    raw = value or ""
    if any(ord(character) < 32 or ord(character) == 127 for character in raw):
        raise ToolArgumentError("The target host contains a control character.")
    host = raw.strip().strip("[]").lower()
    if not host:
        raise ToolArgumentError("A target host is required.")
    if host.startswith("-"):
        raise ToolArgumentError("The target host must not begin with '-'.")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if not _HOST_RE.match(host):
        raise ToolArgumentError("The target host is not a valid DNS name or IP address.")
    return host


def validate_port(value: int | str | None) -> int | None:
    if value in (None, ""):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ToolArgumentError("The port must be an integer.") from None
    if not 1 <= port <= 65535:
        raise ToolArgumentError("The port must be between 1 and 65535.")
    return port


def validate_http_url(value: str) -> str:
    """Return a canonical absolute ``http(s)`` URL, or raise."""
    candidate = (value or "").strip()
    if not candidate:
        raise ToolArgumentError("A target URL is required.")
    parsed = urlsplit(candidate)
    if parsed.scheme not in ("http", "https"):
        raise ToolArgumentError("The target URL must use http or https.")
    if parsed.username or parsed.password:
        raise ToolArgumentError("Target URLs must not contain embedded credentials.")
    if parsed.fragment:
        raise ToolArgumentError("Target URLs must not contain a fragment.")
    host = validate_target_host(parsed.hostname or "")
    port = validate_port(parsed.port)
    netloc = host if port is None else f"{host}:{port}"
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme}://{netloc}{path}{query}"


def validate_rate(value: int | str | None, *, maximum: int = 1000) -> int | None:
    if value in (None, ""):
        return None
    try:
        rate = int(value)
    except (TypeError, ValueError):
        raise ToolArgumentError("The rate limit must be an integer.") from None
    if not 1 <= rate <= maximum:
        raise ToolArgumentError(f"The rate limit must be between 1 and {maximum}.")
    return rate


# ------------------------------------------------------------------ tool schema
@dataclass(frozen=True)
class ToolSpec:
    """One allow-listed tool.

    ``kind`` is ``"binary"`` for a program the worker launches and ``"service"``
    for a network service (OWASP ZAP) the worker talks to over HTTP.

    ``env_binary`` names an environment variable that may override the binary
    path, for an image where a tool lives somewhere unusual. It is read from the
    *worker's own* environment only - never from a job.
    """

    key: str
    name: str
    kind: str
    category: str            # network | web | tls | discovery | injection | content
    activity: str            # passive | active
    intrusive: bool
    binary: str | None = None
    version_args: tuple[str, ...] = ()
    env_binary: str | None = None
    service_env: str | None = None
    requires_url: bool = True
    requires_host: bool = False
    default_timeout: int = 600
    max_output_bytes: int = 8_000_000
    license: str = ""
    homepage: str = ""
    notes: str = ""

    @property
    def gated(self) -> bool:
        return self.intrusive or self.key in GATED_TOOLS

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "name": self.name,
            "kind": self.kind,
            "category": self.category,
            "activity": self.activity,
            "intrusive": self.intrusive,
            "gated": self.gated,
            "binary": self.binary,
            "requires_url": self.requires_url,
            "requires_host": self.requires_host,
            "default_timeout": self.default_timeout,
            "license": self.license,
            "homepage": self.homepage,
            "notes": self.notes,
        }


TOOLS: dict[str, ToolSpec] = {
    "nmap": ToolSpec(
        key="nmap",
        name="Nmap",
        kind="binary",
        category="network",
        activity="active",
        intrusive=False,
        binary="nmap",
        version_args=("--version",),
        requires_url=False,
        requires_host=True,
        default_timeout=900,
        license="NPSL (GPLv2-derived); free to redistribute with the package",
        homepage="https://nmap.org",
        notes="Connect scan only (-sT); no raw-socket -sS so it runs unprivileged.",
    ),
    "nuclei": ToolSpec(
        key="nuclei",
        name="Nuclei",
        kind="binary",
        category="web",
        activity="active",
        intrusive=False,
        binary="nuclei",
        version_args=("-version",),
        default_timeout=900,
        license="MIT",
        homepage="https://github.com/projectdiscovery/nuclei",
        notes="Runs the bundled templates minus intrusive/dos/fuzz tags.",
    ),
    "zap": ToolSpec(
        key="zap",
        name="OWASP ZAP",
        kind="service",
        category="web",
        activity="passive",
        intrusive=False,
        service_env="ZAP_BASE_URL",
        default_timeout=900,
        license="Apache-2.0",
        homepage="https://www.zaproxy.org",
        notes="Passive spider plus passive scan over the daemon API; active scan stays off.",
    ),
    "nikto": ToolSpec(
        key="nikto",
        name="Nikto",
        kind="binary",
        category="web",
        activity="active",
        intrusive=False,
        binary="nikto",
        version_args=("-Version",),
        default_timeout=900,
        license="GPLv2",
        homepage="https://github.com/sullo/nikto",
        notes="Non-intrusive server checks only (-Tuning 123bde).",
    ),
    "whatweb": ToolSpec(
        key="whatweb",
        name="WhatWeb",
        kind="binary",
        category="discovery",
        activity="passive",
        intrusive=False,
        binary="whatweb",
        version_args=("--version",),
        default_timeout=300,
        license="GPLv3",
        homepage="https://github.com/urbanadventurer/WhatWeb",
        notes="Aggression level 1 (stealthy), single request per plugin.",
    ),
    "testssl": ToolSpec(
        key="testssl",
        name="testssl.sh",
        kind="binary",
        category="tls",
        activity="passive",
        intrusive=False,
        binary="testssl",
        env_binary="TESTSSL_BIN",
        version_args=("--version",),
        default_timeout=900,
        license="GPLv2",
        homepage="https://github.com/drwetter/testssl.sh",
        notes="--fast profile; no --warnings banner grab beyond the standard checks.",
    ),
    "sqlmap": ToolSpec(
        key="sqlmap",
        name="SQLmap",
        kind="binary",
        category="injection",
        activity="active",
        intrusive=True,
        binary="sqlmap",
        version_args=("--version",),
        default_timeout=900,
        license="GPLv2",
        homepage="https://sqlmap.org",
        notes="Gated: requires a per-job intrusive authorisation. Never on by default.",
    ),
    "gobuster": ToolSpec(
        key="gobuster",
        name="Gobuster",
        kind="binary",
        category="content",
        activity="active",
        intrusive=True,
        binary="gobuster",
        version_args=("version",),
        default_timeout=900,
        license="Apache-2.0",
        homepage="https://github.com/OJ/gobuster",
        notes="Gated: requires a per-job intrusive authorisation. Uses a fixed wordlist.",
    ),
}


def get_tool(key: str) -> ToolSpec:
    spec = TOOLS.get((key or "").strip().lower())
    if spec is None:
        raise ToolArgumentError(f"Unknown tool {key!r}. It is not in the allow-list.")
    return spec


def resolve_tools(keys) -> tuple[ToolSpec, ...]:
    return tuple(get_tool(key) for key in keys)


# ----------------------------------------------------------------- job request
@dataclass(frozen=True)
class ScanRequest:
    """A fully validated job, ready to be turned into command lines."""

    profile: str
    tools: tuple[str, ...]
    url: str | None = None
    host: str | None = None
    port: int | None = None
    rate_limit: int | None = None
    intrusive: bool = False
    authorized_cidrs: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "profile": self.profile,
            "tools": list(self.tools),
            "url": self.url,
            "host": self.host,
            "port": self.port,
            "rate_limit": self.rate_limit,
            "intrusive": self.intrusive,
            "authorized_cidrs": list(self.authorized_cidrs),
        }


def build_command(
    spec: ToolSpec,
    request: ScanRequest,
    *,
    output_path: str | None = None,
    wordlist: str | None = None,
    templates_path: str | None = None,
) -> list[str]:
    """Return the fixed argv for ``spec`` against ``request``.

    Paths are worker-controlled (temporary output, fixed wordlist, approved
    template directory). No caller value ever reaches argv except the validated
    target and numeric rate.
    """
    url = request.url
    host = request.host
    rate = request.rate_limit

    if spec.key == "nmap":
        argv = [spec.binary, "-oX", "-", "-sT", "-sV", "-T3", "--max-retries", "2"]
        if rate:
            argv += ["--max-rate", str(rate)]
        if request.port:
            argv += ["-p", str(request.port)]
        argv.append(host or "")
        return argv

    if spec.key == "nuclei":
        if not templates_path:
            raise ToolArgumentError("Nuclei is disabled until an approved template directory is configured.")
        argv = [
            spec.binary, "-jsonl", "-silent", "-no-color", "-duc",
            "-t", templates_path, "-target", url or "",
        ]
        if rate:
            argv += ["-rate-limit", str(rate)]
        if not request.intrusive:
            argv += ["-exclude-tags", "intrusive,dos,fuzz"]
        return argv

    if spec.key == "nikto":
        argv = [spec.binary, "-h", url or "", "-nointeractive", "-ask", "no",
                "-Tuning", "123bde", "-o", output_path or "-", "-Format", "json"]
        return argv

    if spec.key == "whatweb":
        argv = [spec.binary, "--log-json", output_path or "-", "--no-errors",
                "--aggression", "1", url or ""]
        return argv

    if spec.key == "testssl":
        argv = [spec.binary, "--jsonfile", output_path or "-", "--quiet", "--color", "0",
                "--fast", url or ""]
        return argv

    if spec.key == "sqlmap":
        argv = [spec.binary, "-u", url or "", "--batch", "--smart", "--level", "1",
                "--risk", "1", "--threads", "1", "--output-dir", output_path or "."]
        return argv

    if spec.key == "gobuster":
        argv = [spec.binary, "dir", "-u", url or "", "-w", wordlist or "",
                "-q", "--no-error", "-t", str(min(int(rate or 10), 10))]
        return argv

    raise ToolArgumentError(f"{spec.key!r} cannot be built into a command line.")


__all__ = [
    "GATED_TOOLS",
    "TOOLS",
    "TOOL_ORDER",
    "ScanRequest",
    "ToolArgumentError",
    "ToolSpec",
    "build_command",
    "get_tool",
    "resolve_tools",
    "validate_http_url",
    "validate_port",
    "validate_rate",
    "validate_target_host",
]
