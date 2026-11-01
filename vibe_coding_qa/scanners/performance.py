"""Performance scanner: bundle/debug artifacts, large assets, INP hints."""

import re
from pathlib import Path

from . import BaseScanner, is_likely_client_file
from vibe_coding_qa import Finding, Severity


class PerformanceScanner(BaseScanner):
    module = "performance"
    LARGE_FILE_BYTES = 500_000
    LARGE_IMAGE_BYTES = 500_000

    def scan(self) -> list[Finding]:
        for path in self.iter_source_files((".ts", ".tsx", ".js", ".jsx", ".py")):
            self._scan_source(path)
        for path in self.repo.rglob("*"):
            if not path.is_file():
                continue
            if "node_modules" in path.parts or ".git" in path.parts:
                continue
            self._scan_asset(path)
        return self.findings

    def _scan_source(self, path: Path) -> None:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for i, raw in enumerate(text.splitlines(), 1):
            if re.search(r"scheduler\.yield\s*\(\)|yield\s+to\s+main", raw, re.IGNORECASE):
                # Positive signal; skip further INP warnings in this file.
                return
            if re.search(r"(onClick|onSubmit|onChange)\s*=\s*\{?\s*(async\s+)?function", raw, re.IGNORECASE):
                # Heuristic: handlers that do heavy work without yielding.
                pass
        # Large synchronous-looking loops in handlers.
        for i, raw in enumerate(text.splitlines(), 1):
            if re.search(r"for\s*\([^)]*\)\s*\{[^}]*\b(fetch|await|compute|process)\b", raw, re.IGNORECASE):
                if is_likely_client_file(path):
                    self.add(
                        rule="potential-blocking-handler",
                        severity=Severity.LOW,
                        file=path,
                        line=i,
                        message="Loop in an event handler may block the main thread.",
                        suggestion="Yield to the main thread with scheduler.yield() or break work into chunks.",
                        confidence="low",
                    )

    def _scan_asset(self, path: Path) -> None:
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg"}:
            try:
                size = path.stat().st_size
            except OSError:
                return
            if size > self.LARGE_IMAGE_BYTES:
                self.add(
                    rule="large-unoptimized-image",
                    severity=Severity.LOW,
                    file=path,
                    line=1,
                    message=f"Image is {size / 1024:.0f} KB; consider compression or modern formats.",
                    suggestion="Compress images, serve WebP/AVIF, and use responsive sizes.",
                    confidence="high",
                )
        elif path.suffix.lower() in {".js", ".css", ".ts", ".tsx"}:
            try:
                size = path.stat().st_size
            except OSError:
                return
            if size > self.LARGE_FILE_BYTES:
                self.add(
                    rule="large-source-file",
                    severity=Severity.LOW,
                    file=path,
                    line=1,
                    message=f"Source file is {size / 1024:.0f} KB; consider splitting.",
                    suggestion="Split large modules to improve loading and caching.",
                    confidence="low",
                )
