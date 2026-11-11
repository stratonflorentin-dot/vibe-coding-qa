"""The shared finding schema every tool adapter normalises into.

A finding is the unit the whole Security Lab is built on: the API persists it,
the dashboard renders it, the AI explains it and the verification workflow
re-tests it. Two identifiers make de-duplication work across tools:

* ``fingerprint`` - identity *within one tool* (tool + endpoint + title). The
  same check firing again on a later scan is "the same finding, seen again".
* ``dedupe_key`` - identity *across tools* (endpoint + normalised title). When
  Nuclei and Nikto both report a missing security header, they fold into one row
  whose ``tools`` list records both sources.

The schema is deliberately plain: adapters build it from parsed tool output with
no knowledge of the database, so a malformed tool result can only ever produce a
malformed *finding*, never a crash or a query the caller controls.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

#: Canonical severities, most severe first.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

#: Canonical confidence levels.
CONFIDENCES: tuple[str, ...] = ("high", "medium", "low")

_SEVERITY_ALIASES = {
    "critical": "critical", "crit": "critical", "4": "critical", "severe": "critical",
    "high": "high", "3": "high", "error": "high",
    "medium": "medium", "med": "medium", "moderate": "medium", "2": "medium", "warn": "medium",
    "warning": "medium",
    "low": "low", "1": "low",
    "info": "info", "informational": "info", "information": "info", "0": "info",
    "note": "info", "ok": "info", "unknown": "info",
}

_CONFIDENCE_ALIASES = {
    "certain": "high", "confirmed": "high", "high": "high", "3": "high",
    "firm": "medium", "medium": "medium", "moderate": "medium", "2": "medium",
    "tentative": "low", "low": "low", "1": "low",
}

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_severity(value: str | None, *, default: str = "info") -> str:
    return _SEVERITY_ALIASES.get((value or "").strip().lower(), default)


def normalize_confidence(value: str | None, *, default: str = "medium") -> str:
    return _CONFIDENCE_ALIASES.get((value or "").strip().lower(), default)


def _slug(value: str) -> str:
    return _SLUG_RE.sub("-", (value or "").lower()).strip("-")


def _digest(*parts: str) -> str:
    return hashlib.sha1("\x1f".join(parts).encode("utf-8", "replace")).hexdigest()[:32]


def dedupe_key_for(*, endpoint: str | None, title: str, category: str | None) -> str:
    """Tool-agnostic identity: labels vary by tool, endpoint/title do not."""
    return f"{_slug(endpoint or '')}|{_slug(title)}"


def fingerprint_for(*, tool: str, endpoint: str | None, title: str) -> str:
    """Tool-scoped identity: a stable name for this tool's repeat sightings."""
    return _digest(_slug(tool), _slug(endpoint or ""), _slug(title))


@dataclass
class Finding:
    """One normalised vulnerability observation."""

    tool: str
    title: str
    severity: str
    target: str
    tool_version: str | None = None
    endpoint: str | None = None
    category: str | None = None
    description: str | None = None
    confidence: str = "medium"
    evidence: str | None = None
    remediation: str | None = None
    references: list[str] = field(default_factory=list)
    detected_at: str = field(default_factory=utcnow)

    def __post_init__(self) -> None:
        # Never trust tool output to be well-formed: coerce everything into the
        # canonical shape here so no downstream consumer has to defend itself.
        self.severity = normalize_severity(self.severity)
        self.confidence = normalize_confidence(self.confidence)
        self.title = (self.title or "Unnamed finding").strip()[:300]
        self.target = (self.target or "").strip()[:500]
        self.endpoint = (self.endpoint or "").strip()[:500] or None
        self.description = _clip(self.description, 4000)
        self.evidence = _clip(self.evidence, 8000)
        self.remediation = _clip(self.remediation, 4000)
        self.references = [str(ref).strip()[:200] for ref in (self.references or []) if str(ref).strip()][:25]

    @property
    def fingerprint(self) -> str:
        return fingerprint_for(tool=self.tool, endpoint=self.endpoint, title=self.title)

    @property
    def dedupe_key(self) -> str:
        return dedupe_key_for(endpoint=self.endpoint, title=self.title, category=self.category)

    @property
    def reference(self) -> str | None:
        """The primary CVE/CWE reference, when a tool supplied one."""
        for ref in self.references:
            if ref.upper().startswith(("CVE-", "CWE-")) or "CVE-" in ref.upper() or "CWE-" in ref.upper():
                return ref
        return self.references[0] if self.references else None

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "tool_version": self.tool_version,
            "target": self.target,
            "endpoint": self.endpoint,
            "title": self.title,
            "category": self.category,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
            "detected_at": self.detected_at,
            "fingerprint": self.fingerprint,
            "dedupe_key": self.dedupe_key,
        }


def _clip(value: str | None, limit: int) -> str | None:
    if not value:
        return None
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "\n...[truncated]"


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Fold findings that share a ``dedupe_key``, keeping the most severe.

    Severity is the tie-breaker because the same issue reported as "medium" by
    one tool and "high" by another must surface at the higher severity; the
    lower-severity duplicate only contributes to the record, which the store
    already merges into the ``tools`` list.
    """
    order = {name: index for index, name in enumerate(SEVERITIES)}
    best: dict[str, Finding] = {}
    for finding in findings:
        current = best.get(finding.dedupe_key)
        if current is None or order[finding.severity] < order[current.severity]:
            best[finding.dedupe_key] = finding
    return list(best.values())


__all__ = [
    "CONFIDENCES",
    "SEVERITIES",
    "Finding",
    "dedupe",
    "dedupe_key_for",
    "fingerprint_for",
    "normalize_confidence",
    "normalize_severity",
    "utcnow",
]
