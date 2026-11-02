"""Dependency, lockfile, CI, and supply-chain scanner."""

import json
import re
from pathlib import Path

from . import BaseScanner
from vibe_coding_qa import Finding, Severity


class DependencyScanner(BaseScanner):
    module = "dependencies"

    KNOWN_EOL = {
        "lodash": "4.17.21",  # earlier versions have known vulnerabilities
        "express": "4.17.3",
        "jquery": "3.6.0",
        "bootstrap": "4.6.1",
    }

    def scan(self) -> list[Finding]:
        self._scan_package_json()
        self._scan_python_deps()
        self._scan_lockfile_consistency()
        self._scan_ci_workflows()
        self._scan_dockerfile()
        self._scan_github_actions()
        return self.findings

    def _scan_package_json(self) -> None:
        pkg = self.repo / "package.json"
        if not pkg.is_file():
            return
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        for name, version in deps.items():
            cleaned = version.strip().lstrip("^~>=<")
            if name in self.KNOWN_EOL:
                try:
                    if self._version_tuple(cleaned) < self._version_tuple(self.KNOWN_EOL[name]):
                        self.add(
                            rule="outdated-dependency",
                            severity=Severity.MEDIUM,
                            file=pkg,
                            line=1,
                            message=f"{name}@{version} is below the recommended floor ({self.KNOWN_EOL[name]}).",
                            suggestion="Upgrade to a supported version and review the dependency's changelog for security fixes.",
                            confidence="medium",
                        )
                except Exception:
                    pass
            if name in {"left-pad", "event-stream", "flatmap-stream"}:
                self.add(
                    rule="known-malicious-dependency",
                    severity=Severity.CRITICAL,
                    file=pkg,
                    line=1,
                    message=f"Dependency '{name}' has a documented malicious history.",
                    suggestion="Remove and replace this dependency immediately.",
                    confidence="high",
                )

    def _scan_python_deps(self) -> None:
        req = self.repo / "requirements.txt"
        if not req.is_file():
            return
        for i, raw in enumerate(req.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "==" not in line:
                self.add(
                    rule="unpinned-python-dependency",
                    severity=Severity.LOW,
                    file=req,
                    line=i,
                    message="Python dependency is not pinned.",
                    suggestion="Pin versions and use a lockfile for reproducible, auditable builds.",
                    confidence="low",
                )

    def _scan_lockfile_consistency(self) -> None:
        pkg = self.repo / "package.json"
        has_lock = any((self.repo / name).is_file() for name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"))
        if pkg.is_file() and not has_lock:
            self.add(
                rule="missing-lockfile",
                severity=Severity.MEDIUM,
                file=pkg,
                line=1,
                message="package.json exists without a lockfile.",
                suggestion="Commit a lockfile to ensure reproducible installs and supply-chain audits.",
                confidence="high",
            )
        lock_age = None
        for name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
            lock = self.repo / name
            if lock.is_file():
                lock_age = lock.stat().st_mtime
                break
        pkg_age = pkg.stat().st_mtime if pkg.is_file() else None
        if lock_age and pkg_age and abs(lock_age - pkg_age) > 86400:
            # Heuristic only; lockfile could still be current.
            pass

    def _scan_ci_workflows(self) -> None:
        workflows = self.repo / ".github" / "workflows"
        if not workflows.is_dir():
            return
        for path in workflows.glob("*.yml"):
            self._check_workflow(path)
        for path in workflows.glob("*.yaml"):
            self._check_workflow(path)

    def _check_workflow(self, path: Path) -> None:
        text = path.read_text(encoding="utf-8", errors="ignore").lower()
        lines = text.splitlines()
        for i, raw in enumerate(lines, 1):
            lowered = raw.lower()
            if "pull_request_target" in lowered:
                self.add(
                    rule="ci-pull-request-target",
                    severity=Severity.HIGH,
                    file=path,
                    line=i,
                    message="Workflow uses pull_request_target; review for cache/p checkout injection risks.",
                    suggestion="Prefer pull_request where possible, pin checkout ref to the merge commit, and avoid running untrusted code with secrets.",
                    confidence="medium",
                )
            if "actions/checkout@v1" in lowered or "actions/checkout@v2" in lowered:
                self.add(
                    rule="ci-outdated-checkout",
                    severity=Severity.LOW,
                    file=path,
                    line=i,
                    message="Workflow uses an old actions/checkout version.",
                    suggestion="Upgrade to actions/checkout@v4 and set persist-credentials: false when not needed.",
                    confidence="medium",
                )
            if re.search(r"secrets\.[a-z0-9_]+", raw, re.IGNORECASE) and ("pull_request" in text or "pull_request_target" in text):
                # Only flag if not in an environment context.
                if "environment:" not in raw and "environment:" not in "\n".join(lines[max(0, i - 5):i]):
                    self.add(
                        rule="ci-secret-in-pr-workflow",
                        severity=Severity.MEDIUM,
                        file=path,
                        line=i,
                        message="Workflow may expose secrets to pull-request builds.",
                        suggestion="Scope secrets to protected environments and avoid using them in jobs triggered by forks.",
                        confidence="low",
                    )

    def _scan_dockerfile(self) -> None:
        for path in self.repo.rglob("Dockerfile*"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            for i, raw in enumerate(text.splitlines(), 1):
                if re.search(r"^FROM\s+.*:latest", raw, re.IGNORECASE):
                    self.add(
                        rule="docker-latest-tag",
                        severity=Severity.LOW,
                        file=path,
                        line=i,
                        message="Docker base image uses the :latest tag.",
                        suggestion="Pin a specific digest or version tag for reproducible builds.",
                        confidence="medium",
                    )
                if re.search(r"^USER\s+root\s*$", raw, re.IGNORECASE):
                    self.add(
                        rule="docker-root-user",
                        severity=Severity.MEDIUM,
                        file=path,
                        line=i,
                        message="Dockerfile explicitly runs as root.",
                        suggestion="Create and switch to a non-root user after installing dependencies.",
                        confidence="medium",
                    )
                if re.search(r"EXPOSE\s+\d+", raw, re.IGNORECASE) and "EXPOSE 443" not in raw.upper():
                    self.add(
                        rule="docker-exposed-port-review",
                        severity=Severity.INFO,
                        file=path,
                        line=i,
                        message="Dockerfile exposes a port; confirm TLS terminates at the edge.",
                        suggestion="Terminate TLS at the reverse proxy or load balancer; do not expose plain HTTP directly.",
                        confidence="low",
                    )

    def _scan_github_actions(self) -> None:
        # Additional high-level checks already covered in _scan_ci_workflows.
        pass

    @staticmethod
    def _version_tuple(version: str):
        return tuple(int(p) for p in re.split(r"[.-]", version) if p.isdigit())
