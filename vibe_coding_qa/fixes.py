"""Automated fix engine: apply safe, reviewable fixes."""

import re
from pathlib import Path

from . import Finding, Severity


class FixEngine:
    def __init__(self, repo: Path, dry_run: bool = True):
        self.repo = repo
        self.dry_run = dry_run
        self.applied: list[dict] = []
        self.skipped: list[dict] = []

    def apply(self, findings: list[Finding]) -> dict:
        for finding in findings:
            if not finding.fixable:
                self.skipped.append({"finding": finding.to_dict(), "reason": "not marked fixable"})
                continue
            method_name = f"fix_{finding.rule.replace(':', '_').replace('-', '_')}"
            method = getattr(self, method_name, None)
            if method is None:
                self.skipped.append({"finding": finding.to_dict(), "reason": "no automated fix available"})
                continue
            try:
                method(finding)
            except Exception as exc:
                self.skipped.append({"finding": finding.to_dict(), "reason": str(exc)})
        return {"applied": self.applied, "skipped": self.skipped, "dry_run": self.dry_run}

    def _read(self, file: Path) -> list[str]:
        path = self.repo / file
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()

    def _write(self, file: Path, lines: list[str]) -> None:
        if self.dry_run:
            return
        path = self.repo / file
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    def fix_quality_console_log_in_production(self, finding: Finding) -> None:
        lines = self._read(finding.file)
        i = finding.line - 1
        if i < 0 or i >= len(lines):
            raise IndexError("line out of range")
        original = lines[i]
        # Remove the whole statement if it is a simple console.log/debug/warn call.
        cleaned = re.sub(r"\s*console\.(log|debug|warn)\s*\([^;]*\);?", "", original)
        if cleaned == original or not cleaned.strip():
            cleaned = re.sub(r"console\.(log|debug|warn)\s*\([^;]*\);?", "", original)
        lines[i] = cleaned
        self._write(finding.file, lines)
        self.applied.append({"finding": finding.to_dict(), "replacement": cleaned})

    def fix_quality_debugger_statement(self, finding: Finding) -> None:
        lines = self._read(finding.file)
        i = finding.line - 1
        if i < 0 or i >= len(lines):
            raise IndexError("line out of range")
        original = lines[i]
        cleaned = re.sub(r"\s*debugger;?", "", original)
        lines[i] = cleaned
        self._write(finding.file, lines)
        self.applied.append({"finding": finding.to_dict(), "replacement": cleaned})

    def fix_security_client_side_secret(self, finding: Finding) -> None:
        # Unsafe to auto-fix; require manual migration to server route.
        raise RuntimeError("client-side secrets require moving the value to a server route; cannot auto-fix")

    def fix_security_committed_env_file(self, finding: Finding) -> None:
        # We can suggest but not safely delete tracked files without git operations.
        raise RuntimeError("remove the file from git and rotate secrets; cannot auto-fix")


def suggest_fixes(findings: list[Finding]) -> list[dict]:
    """Generate human-readable suggestions without modifying files."""
    suggestions = []
    for f in findings:
        suggestions.append({
            "file": str(f.file),
            "line": f.line,
            "rule": f.rule,
            "severity": f.severity.value,
            "message": f.message,
            "suggestion": f.suggestion,
            "auto_fixable": f.fixable,
        })
    return suggestions
