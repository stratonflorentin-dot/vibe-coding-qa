"""Vibe Coding QA Engine.

Turns the vibe-coding-qa framework into an automated production-readiness
engineering tool that can inspect real repositories, report findings with file
and line references, suggest or apply fixes, rerun tests, and block release
when critical issues remain.
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    BLOCK = "block"


@dataclass(frozen=True)
class Finding:
    rule: str
    module: str
    severity: Severity
    file: Path
    line: int
    column: int = 0
    message: str = ""
    suggestion: str = ""
    confidence: str = "medium"  # low, medium, high
    fixable: bool = False
    auto_fix: str = ""  # replacement snippet when safe

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "module": self.module,
            "severity": self.severity.value,
            "file": str(self.file),
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "suggestion": self.suggestion,
            "confidence": self.confidence,
            "fixable": self.fixable,
            "auto_fix": self.auto_fix,
        }


@dataclass
class ModuleResult:
    module: str
    status: Status
    score: float  # 0.0 - 100.0
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "status": self.status.value,
            "score": round(self.score, 2),
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes,
        }


@dataclass
class ScanResult:
    repo: Path
    modules: list[ModuleResult]
    tests: dict[str, Any] = field(default_factory=dict)

    @property
    def findings(self) -> list[Finding]:
        return [f for m in self.modules for f in m.findings]

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def overall_score(self) -> float:
        if not self.modules:
            return 0.0
        return round(sum(m.score for m in self.modules) / len(self.modules), 2)

    @property
    def release_blocked(self) -> bool:
        if self.critical_count > 0:
            return True
        if self.tests.get("status") == Status.FAIL:
            return True
        return any(m.status == Status.BLOCK for m in self.modules)

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo": str(self.repo),
            "overall_score": self.overall_score,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "release_blocked": self.release_blocked,
            "tests": self.tests,
            "modules": [m.to_dict() for m in self.modules],
        }
