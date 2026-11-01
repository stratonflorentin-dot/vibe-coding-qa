"""Quality scanner: TypeScript/JavaScript/Python static checks."""

import re
from pathlib import Path

from . import BaseScanner, is_likely_client_file, is_test_or_fixture
from vibe_coding_qa import Finding, Severity


class QualityScanner(BaseScanner):
    module = "quality"

    def scan(self) -> list[Finding]:
        for path in self.iter_source_files((".ts", ".tsx", ".js", ".jsx", ".py")):
            self._scan_console_logs(path)
            self._scan_todos(path)
            self._scan_any_types(path)
            self._scan_missing_error_boundaries(path)
            self._scan_debugger_statements(path)
        self._scan_build_config()
        return self.findings

    def _scan_console_logs(self, path: Path) -> None:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for i, raw in enumerate(text.splitlines(), 1):
            if re.search(r"(?<!\w)console\.(log|debug|warn)\s*\(", raw):
                if is_test_or_fixture(path):
                    continue
                self.add(
                    rule="console-log-in-production",
                    severity=Severity.LOW,
                    file=path,
                    line=i,
                    message="Console logging statement found in source code.",
                    suggestion="Remove console.log/debug/warn from production builds or route through a logging service.",
                    confidence="high",
                    fixable=True,
                )

    def _scan_todos(self, path: Path) -> None:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for i, raw in enumerate(text.splitlines(), 1):
            if re.search(r"(?<!\w)(TODO|FIXME|HACK|XXX)\s*[:\(]", raw, re.IGNORECASE):
                self.add(
                    rule="unfinished-todo",
                    severity=Severity.LOW,
                    file=path,
                    line=i,
                    message="Unresolved TODO/FIXME/HACK marker found.",
                    suggestion="Resolve or ticket the item before release.",
                    confidence="high",
                )

    def _scan_any_types(self, path: Path) -> None:
        if path.suffix not in {".ts", ".tsx"}:
            return
        text = path.read_text(encoding="utf-8", errors="ignore")
        for i, raw in enumerate(text.splitlines(), 1):
            if ": any" in raw or "as any" in raw or "<any>" in raw:
                self.add(
                    rule="unsafe-any-type",
                    severity=Severity.MEDIUM,
                    file=path,
                    line=i,
                    message="Unsafe `any` type assertion detected.",
                    suggestion="Replace `any` with a specific interface or use `unknown` with a type guard.",
                    confidence="medium",
                )

    def _scan_missing_error_boundaries(self, path: Path) -> None:
        if not is_likely_client_file(path) or path.suffix not in {".tsx", ".jsx"}:
            return
        text = path.read_text(encoding="utf-8", errors="ignore")
        # Only flag if a component file has no error boundary and is reasonably large.
        if "ErrorBoundary" in text or "error boundary" in text.lower():
            return
        if len(text.splitlines()) < 40:
            return
        self.add(
            rule="missing-error-boundary",
            severity=Severity.MEDIUM,
            file=path,
            line=1,
            message="No React ErrorBoundary detected in this component file.",
            suggestion="Add an error boundary to prevent a single component crash from taking down the whole UI.",
            confidence="low",
        )

    def _scan_debugger_statements(self, path: Path) -> None:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for i, raw in enumerate(text.splitlines(), 1):
            if re.search(r"(?<!\w)debugger;?\s*$", raw):
                self.add(
                    rule="debugger-statement",
                    severity=Severity.LOW,
                    file=path,
                    line=i,
                    message="`debugger` statement left in source.",
                    suggestion="Remove debugger statements before production builds.",
                    confidence="high",
                    fixable=True,
                )

    def _scan_build_config(self) -> None:
        vite = self.repo / "vite.config.ts"
        next_config = self.repo / "next.config.js"
        for path in (vite, next_config):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for i, raw in enumerate(text.splitlines(), 1):
                if "sourcemap" in raw.lower() and "false" not in raw.lower():
                    self.add(
                        rule="source-maps-enabled",
                        severity=Severity.LOW,
                        file=path,
                        line=i,
                        message="Source maps may be enabled in production build config.",
                        suggestion="Disable source maps in production to avoid exposing source code.",
                        confidence="low",
                    )
                if "console" in raw.lower() and "drop" in raw.lower():
                    # Config removes console logs; clear prior findings is done in engine, not here.
                    pass
