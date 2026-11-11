"""Quality scanner: TypeScript/JavaScript/Python static checks."""

import re
from pathlib import Path

from . import BaseScanner, load_ignore_patterns, is_ignored, is_likely_client_file, is_test_or_fixture
from vibe_coding_qa import Finding, Severity


class QualityScanner(BaseScanner):
    module = "quality"

    def scan(self) -> list[Finding]:
        ignore = load_ignore_patterns(self.repo)
        for path in self.iter_source_files((".ts", ".tsx", ".js", ".jsx", ".py")):
            if is_ignored(path, self.repo, ignore):
                continue
            self._scan_console_logs(path)
            self._scan_todos(path)
            self._scan_any_types(path)
            self._scan_debugger_statements(path)
        self._scan_error_boundary_coverage(ignore)
        self._scan_build_config(ignore)
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

    #: Signals that a file wires a real React error boundary (not a stray mention).
    _ERROR_BOUNDARY_SIGNAL = re.compile(
        r"class\s+\w*ErrorBoundary\b"
        r"|getDerivedStateFromError"
        r"|componentDidCatch"
        r"|<ErrorBoundary[\s/>]"
        r"|withErrorBoundary\s*\(",
    )

    def _scan_error_boundary_coverage(self, ignore: list[str]) -> None:
        """Flag a React client app whose render tree has no error boundary at all.

        A single top-level (and ideally per-route) ``ErrorBoundary`` keeps one
        component's crash from taking down the whole UI. That is an app-level
        property: error boundaries belong at the root and route boundaries, not
        inside every component, hook, context provider or UI primitive. So
        coverage is assessed once across the client tree rather than demanded of
        each file — which previously produced a false positive for every sizable
        component. An app with no boundary anywhere is still flagged at its root.
        """
        client_files = [
            p
            for p in self.iter_source_files((".tsx", ".jsx"))
            if not is_ignored(p, self.repo, ignore) and is_likely_client_file(p, self.repo)
        ]
        if not client_files:
            return
        for path in client_files:
            if self._ERROR_BOUNDARY_SIGNAL.search(path.read_text(encoding="utf-8", errors="ignore")):
                return  # The app wires at least one real error boundary.
        roots = [p for p in client_files if p.name.lower() in {"main.tsx", "index.tsx", "app.tsx", "main.jsx", "index.jsx", "app.jsx"}]
        for path in roots or client_files[:1]:
            self.add(
                rule="missing-error-boundary",
                severity=Severity.MEDIUM,
                file=path,
                line=1,
                message="No React ErrorBoundary found anywhere in the client app.",
                suggestion="Add an ErrorBoundary at the app root and around routed pages so one component crash cannot take down the whole UI.",
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

    def _scan_build_config(self, ignore: list[str]) -> None:
        vite = self.repo / "vite.config.ts"
        next_config = self.repo / "next.config.js"
        for path in (vite, next_config):
            if not path.is_file():
                continue
            if is_ignored(path, self.repo, ignore):
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
