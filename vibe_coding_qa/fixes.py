"""Automated fix engine: apply safe, reviewable fixes."""

import difflib
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from . import Finding, Severity


class FixClassification:
    SAFE = "safe-automatic"
    APPROVAL = "approval-required"
    MANUAL = "manual-remediation"


class FixEngine:
    def __init__(self, repo: Path, dry_run: bool = True):
        self.repo = repo
        self.dry_run = dry_run
        self.applied: list[dict] = []
        self.skipped: list[dict] = []
        self.backups: list[Path] = []
        self.backup_dir = repo / ".vcqa-backups" / datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

    def apply(self, findings: list[Finding]) -> dict:
        for finding in findings:
            if not finding.fixable:
                self.skipped.append({"finding": finding.to_dict(), "reason": "not marked fixable", "classification": FixClassification.MANUAL})
                continue
            classification = self.classify(finding)
            if classification == FixClassification.MANUAL:
                self.skipped.append({"finding": finding.to_dict(), "reason": "manual remediation required", "classification": classification})
                continue
            if classification == FixClassification.APPROVAL:
                self.skipped.append({"finding": finding.to_dict(), "reason": "requires explicit approval", "classification": classification})
                continue
            method_name = f"fix_{finding.rule.replace(':', '_').replace('-', '_')}"
            method = getattr(self, method_name, None)
            if method is None:
                self.skipped.append({"finding": finding.to_dict(), "reason": "no automated fix available", "classification": classification})
                continue
            try:
                method(finding)
            except Exception as exc:
                self.skipped.append({"finding": finding.to_dict(), "reason": str(exc), "classification": classification})
        return {"applied": self.applied, "skipped": self.skipped, "dry_run": self.dry_run}

    def classify(self, finding: Finding) -> str:
        if finding.severity in (Severity.CRITICAL,):
            return FixClassification.APPROVAL
        if finding.rule in ("security:client-side-secret", "security:committed-env-file"):
            return FixClassification.MANUAL
        if finding.rule in ("quality:console-log-in-production", "quality:debugger-statement"):
            return FixClassification.SAFE
        return FixClassification.APPROVAL

    def _resolve_path(self, file: Path) -> Path:
        target = self.repo / file
        resolved = target.resolve()
        repo_resolved = self.repo.resolve()
        # Prevent symlink/path traversal escape.
        if not str(resolved).startswith(str(repo_resolved) + os.sep) and resolved != repo_resolved:
            raise ValueError(f"Target path escapes repository: {file}")
        return resolved

    def _read(self, file: Path) -> list[str]:
        path = self._resolve_path(file)
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()

    def _backup(self, path: Path) -> Path:
        if self.dry_run:
            return path
        rel = path.relative_to(self.repo.resolve())
        backup = self.backup_dir / rel
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, backup)
        self.backups.append(backup)
        return backup

    def _write(self, file: Path, lines: list[str]) -> None:
        path = self._resolve_path(file)
        self._backup(path)
        if self.dry_run:
            return
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    def _make_diff(self, original_lines: list[str], new_lines: list[str], file: Path) -> str:
        return "\n".join(difflib.unified_diff(
            original_lines,
            new_lines,
            fromfile=str(file),
            tofile=str(file),
            lineterm="",
        ))

    def fix_quality_console_log_in_production(self, finding: Finding) -> None:
        lines = self._read(finding.file)
        original = list(lines)
        i = finding.line - 1
        if i < 0 or i >= len(lines):
            raise IndexError("line out of range")
        line = lines[i]
        cleaned = re.sub(r"\s*console\.(log|debug|warn)\s*\([^;]*\);?", "", line)
        if cleaned == line or not cleaned.strip():
            cleaned = re.sub(r"console\.(log|debug|warn)\s*\([^;]*\);?", "", line)
        lines[i] = cleaned
        diff = self._make_diff(original, lines, finding.file)
        self._write(finding.file, lines)
        self.applied.append({"finding": finding.to_dict(), "replacement": cleaned, "diff": diff, "classification": FixClassification.SAFE})

    def fix_quality_debugger_statement(self, finding: Finding) -> None:
        lines = self._read(finding.file)
        original = list(lines)
        i = finding.line - 1
        if i < 0 or i >= len(lines):
            raise IndexError("line out of range")
        line = lines[i]
        cleaned = re.sub(r"\s*debugger;?", "", line)
        lines[i] = cleaned
        diff = self._make_diff(original, lines, finding.file)
        self._write(finding.file, lines)
        self.applied.append({"finding": finding.to_dict(), "replacement": cleaned, "diff": diff, "classification": FixClassification.SAFE})

    def fix_security_client_side_secret(self, finding: Finding) -> None:
        raise RuntimeError("client-side secrets require moving the value to a server route; cannot auto-fix")

    def fix_security_committed_env_file(self, finding: Finding) -> None:
        raise RuntimeError("remove the file from git and rotate secrets; cannot auto-fix")

    def rollback(self, backup: Path | None = None) -> list[Path]:
        """Restore the most recent backup, or a specific backup path."""
        if backup is None:
            if not self.backups:
                return []
            backup = self.backups[-1]
        rel = backup.relative_to(self.backup_dir)
        target = self.repo / rel
        shutil.copy2(backup, target)
        return [target]

    @staticmethod
    def _finding_key(finding: "Finding | dict") -> tuple[str, str]:
        if isinstance(finding, Finding):
            return finding.rule, str(finding.file)
        return str(finding["rule"]), str(finding["file"])

    def verify(self, rescan_findings: list[Finding], tests: dict | None = None) -> dict:
        """Confirm which applied fixes actually removed the detected issue.

        Verification is evidence-based: a fix is only marked ``resolved`` when a
        fresh scan of the modified repository no longer reports the rule for that
        file. It is never inferred from the fact that a file was edited or from a
        shifted line number. When the same rule appears more than once in a file,
        resolutions are counted by multiplicity so a partial fix is reported as
        ``partially_resolved`` rather than ``resolved``.

        If tests were run and failed, no fix can be confirmed and every attempt is
        reported as ``unverifiable`` so a regression is never masked.
        """
        before: dict[tuple[str, str], int] = {}
        changes_by_key: dict[tuple[str, str], list[dict]] = {}
        for change in self.applied:
            key = self._finding_key(change["finding"])
            before[key] = before.get(key, 0) + 1
            changes_by_key.setdefault(key, []).append(change)

        after: dict[tuple[str, str], int] = {}
        for finding in rescan_findings:
            key = self._finding_key(finding)
            after[key] = after.get(key, 0) + 1

        tests_failed = bool(tests and tests.get("status") == "fail")
        report: dict = {
            "resolved": [],
            "partially_resolved": [],
            "unresolved": [],
            "unverifiable": [],
            "tests_failed": tests_failed,
            "verified": False,
        }
        for key, attempted in before.items():
            remaining = after.get(key, 0)
            entry = {"rule": key[0], "file": key[1], "attempted": attempted, "remaining": remaining}
            if tests_failed:
                status = "unverifiable"
            elif remaining == 0:
                status = "resolved"
            elif remaining < attempted:
                status = "partially_resolved"
            else:
                status = "unresolved"
            entry["status"] = status
            report[status].append(entry)
            for change in changes_by_key[key]:
                change["resolution"] = status

        report["verified"] = (
            not tests_failed
            and bool(report["resolved"])
            and not report["partially_resolved"]
            and not report["unresolved"]
        )
        return report


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
