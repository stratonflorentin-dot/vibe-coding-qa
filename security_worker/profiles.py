"""Security worker profiles: explicit tools, impact labels, and rate ceilings."""

from __future__ import annotations

from dataclasses import dataclass

from .registry import ToolArgumentError, get_tool


@dataclass(frozen=True)
class WorkerProfile:
    key: str
    name: str
    description: str
    tools: tuple[str, ...]
    default_rate: int
    max_rate: int
    requires_explicit_authorization: bool = False

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "tools": list(self.tools),
            "default_rate": self.default_rate,
            "max_rate": self.max_rate,
            "requires_explicit_authorization": self.requires_explicit_authorization,
            "activities": [
                {"tool": key, "activity": get_tool(key).activity, "intrusive": get_tool(key).intrusive}
                for key in self.tools
            ],
        }


PROFILES: dict[str, WorkerProfile] = {
    "basic": WorkerProfile(
        "basic", "Basic",
        "TLS checks, technology identification, HTTP headers and safe configuration checks.",
        ("testssl", "whatweb"), default_rate=2, max_rate=5,
    ),
    "network": WorkerProfile(
        "network", "Network",
        "Authorized TCP connect port discovery and service identification.",
        ("nmap",), default_rate=50, max_rate=200,
    ),
    "web": WorkerProfile(
        "web", "Web",
        "Passive OWASP ZAP checks and approved non-intrusive Nuclei templates.",
        ("zap", "nuclei"), default_rate=5, max_rate=25,
    ),
    "vulnerability": WorkerProfile(
        "vulnerability", "Vulnerability",
        "Approved Nuclei vulnerability checks with conservative rate limits and evidence.",
        ("nuclei",), default_rate=3, max_rate=10,
    ),
    "comprehensive": WorkerProfile(
        "comprehensive", "Comprehensive",
        "Combines approved profiles. Requires explicit authorization; no destructive exploitation.",
        ("testssl", "whatweb", "nmap", "zap", "nuclei"),
        default_rate=2, max_rate=5, requires_explicit_authorization=True,
    ),
}


def get_profile(key: str) -> WorkerProfile:
    profile = PROFILES.get((key or "").strip().lower())
    if profile is None:
        raise ToolArgumentError(f"Unknown security scan profile {key!r}.")
    return profile


def validate_job_tools(profile_key: str, tools: list[str] | None, *, intrusive: bool) -> tuple[WorkerProfile, tuple[str, ...]]:
    """Ensure requested tools match the profile and gated tools are authorized."""
    profile = get_profile(profile_key)
    selected = tuple(tools or profile.tools)
    if not selected or len(set(selected)) != len(selected):
        raise ToolArgumentError("Select one or more distinct tools from the selected profile.")
    allowed = set(profile.tools)
    for key in selected:
        spec = get_tool(key)
        if key not in allowed and not (intrusive and spec.gated):
            raise ToolArgumentError(f"Tool {key!r} is not allowed by the {profile.key} profile.")
        if spec.gated and not intrusive:
            raise ToolArgumentError(f"Tool {key!r} requires explicit intrusive authorization.")
    if profile.requires_explicit_authorization and not intrusive:
        raise ToolArgumentError(f"The {profile.name} profile requires explicit authorization.")
    return profile, selected


__all__ = ["PROFILES", "WorkerProfile", "get_profile", "validate_job_tools"]
