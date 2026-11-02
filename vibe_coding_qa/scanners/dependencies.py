"""Dependency, lockfile, CI, and supply-chain scanner.

This scanner performs local, static checks only. It does NOT query external
vulnerability databases. Findings are labeled as 'heuristic' or 'verified'
based on the evidence available locally.
"""

import json
import re
from pathlib import Path

from . import BaseScanner
from vibe_coding_qa import Finding, Severity


class DependencyScanner(BaseScanner):
    module = "dependencies"

    # Known vulnerable versions (historical data, not live advisories)
    # These are examples of versions with known CVEs - in production you would
    # use a proper vulnerability database like OSV, GitHub Advisory, or Snyk.
    KNOWN_VULNERABLE_VERSIONS = {
        "lodash": {
            "versions": ["4.17.20", "4.17.19", "4.17.18", "4.17.17", "4.17.16", "4.17.15", "4.17.14", "4.17.13", "4.17.12", "4.17.11"],
            "cve": "CVE-2021-23337",
            "description": "Prototype pollution in lodash",
        },
        "express": {
            "versions": ["4.17.2", "4.17.1", "4.17.0", "4.16.4", "4.16.3", "4.16.2", "4.16.1", "4.16.0"],
            "cve": "CVE-2022-24999",
            "description": "Open redirect in express",
        },
        "jquery": {
            "versions": ["3.5.1", "3.5.0", "3.4.1", "3.4.0", "3.3.1", "3.3.0", "3.2.1", "3.2.0", "3.1.1", "3.1.0", "3.0.0"],
            "cve": "CVE-2020-11023",
            "description": "XSS in jQuery",
        },
    }

    # Historically compromised packages (supply chain incidents)
    # These are packages that were compromised at some point in history.
    # Presence alone doesn't mean the current version is malicious.
    HISTORICALLY_COMPROMISED = {
        "event-stream": {
            "incident": "event-stream@3.3.6 contained malicious code targeting Copay wallet (Nov 2018)",
            "cve": "CVE-2018-19207",
        },
        "flatmap-stream": {
            "incident": "flatmap-stream@0.1.1 was a malicious dependency of event-stream",
            "cve": "CVE-2018-19207",
        },
        "left-pad": {
            "incident": "left-pad was unpublished in 2016 causing widespread breakage; not malicious but demonstrates supply chain fragility",
            "cve": None,
        },
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
            
            # Check for known vulnerable versions (heuristic based on historical data)
            if name in self.KNOWN_VULNERABLE_VERSIONS:
                vuln_info = self.KNOWN_VULNERABLE_VERSIONS[name]
                if cleaned in vuln_info["versions"]:
                    self.add(
                        rule="vulnerable-dependency",
                        severity=Severity.HIGH,
                        file=pkg,
                        line=1,
                        message=f"{name}@{version} matches a historically vulnerable version ({vuln_info['cve']}: {vuln_info['description']}).",
                        suggestion=f"Upgrade {name} to a patched version. Verify with a current vulnerability database (OSV, GitHub Advisory, npm audit).",
                        confidence="medium",  # Based on historical data, not live check
                    )
            
            # Check for historically compromised packages
            if name in self.HISTORICALLY_COMPROMISED:
                incident = self.HISTORICALLY_COMPROMISED[name]
                self.add(
                    rule="historically-compromised-dependency",
                    severity=Severity.MEDIUM,  # Lower severity - historical incident, not current threat
                    file=pkg,
                    line=1,
                    message=f"Dependency '{name}' was involved in a historical supply-chain incident: {incident['incident']}.",
                    suggestion=f"Verify the current version is not affected. Check {incident['cve'] or 'supply chain advisories'} for details. This is a historical finding, not a confirmed current vulnerability.",
                    confidence="low",  # Historical incident, not current verification
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