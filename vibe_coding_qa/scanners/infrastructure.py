"""Infrastructure scanner: TLS, headers, container, nginx configs."""

import re
from pathlib import Path

from . import BaseScanner, load_ignore_patterns, is_ignored
from vibe_coding_qa import Finding, Severity


class InfrastructureScanner(BaseScanner):
    module = "infrastructure"

    def scan(self) -> list[Finding]:
        ignore = load_ignore_patterns(self.repo)
        self._scan_nginx(ignore)
        self._scan_docker(ignore)
        self._scan_csp(ignore)
        return self.findings

    def _scan_nginx(self, ignore: list[str]) -> None:
        for path in self.repo.rglob("*.conf"):
            if is_ignored(path, self.repo, ignore):
                continue
            if "nginx" not in path.name.lower() and "default" not in path.name.lower():
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            lowered = text.lower()
            for i, raw in enumerate(text.splitlines(), 1):
                norm = raw.strip().lower()
                if "listen 80" in norm and "redirect" not in lowered:
                    self.add(
                        rule="nginx-plain-http-listen",
                        severity=Severity.HIGH,
                        file=path,
                        line=i,
                        message="Nginx listens on plain HTTP without an obvious redirect to HTTPS.",
                        suggestion="Redirect all HTTP traffic to HTTPS before serving content.",
                        confidence="medium",
                    )
                if re.search(r"ssl_protocols\s+.*(sslv2|sslv3|tlsv1\.0|tlsv1\.1)", raw, re.IGNORECASE):
                    self.add(
                        rule="nginx-weak-tls",
                        severity=Severity.CRITICAL,
                        file=path,
                        line=i,
                        message="Nginx enables a deprecated TLS/SSL protocol.",
                        suggestion="Use only TLS 1.2 and TLS 1.3.",
                        confidence="high",
                    )
            if "strict-transport-security" not in lowered:
                self.add(
                    rule="nginx-missing-hsts",
                    severity=Severity.HIGH,
                    file=path,
                    line=1,
                    message="HSTS header not detected in Nginx config.",
                    suggestion="Add add_header Strict-Transport-Security with max-age=63072000; includeSubDomains; preload.",
                    confidence="medium",
                )
            for header in ("x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"):
                if header not in lowered:
                    self.add(
                        rule=f"nginx-missing-{header.replace('-', '_')}",
                        severity=Severity.MEDIUM,
                        file=path,
                        line=1,
                        message=f"{header.upper().replace('-', '-')} header not detected in Nginx config.",
                        suggestion=f"Add the {header.upper().replace('-', '-')} header to every response.",
                        confidence="low",
                    )

    def _scan_docker(self, ignore: list[str]) -> None:
        for path in self.repo.rglob("Dockerfile*"):
            if is_ignored(path, self.repo, ignore):
                continue
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
                if re.search(r"EXPOSE\s+\d+", raw, re.IGNORECASE) and "EXPOSE 443" not in raw.upper():
                    self.add(
                        rule="docker-exposed-port-review",
                        severity=Severity.INFO,
                        file=path,
                        line=i,
                        message="Dockerfile exposes a port; confirm TLS terminates at the edge or reverse proxy.",
                        suggestion="Terminate TLS at the reverse proxy or load balancer; do not expose plain HTTP directly.",
                        confidence="low",
                    )

    def _scan_csp(self, ignore: list[str]) -> None:
        for path in self.iter_source_files((".ts", ".tsx", ".js", ".jsx", ".py")):
            if is_ignored(path, self.repo, ignore):
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for i, raw in enumerate(text.splitlines(), 1):
                if "content-security-policy" in raw.lower():
                    if "unsafe-inline" in raw.lower() or "unsafe-eval" in raw.lower():
                        self.add(
                            rule="csp-unsafe-directive",
                            severity=Severity.MEDIUM,
                            file=path,
                            line=i,
                            message="CSP uses unsafe-inline or unsafe-eval.",
                            suggestion="Use nonces or hashes for scripts and remove unsafe-eval where possible.",
                            confidence="medium",
                        )
                    return
        self.add(
            rule="csp-missing",
            severity=Severity.MEDIUM,
            file=self.repo,
            line=1,
            message="No Content-Security-Policy header detected in source.",
            suggestion="Add a restrictive CSP through Nginx or application middleware.",
            confidence="low",
        )
