"""Base scanner utilities and shared helpers."""

import re
from pathlib import Path

from vibe_coding_qa import Finding, Severity


SECRET_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE), Severity.CRITICAL),
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL),
    ("generic-api-key", re.compile(r"(?<!\w)(api[_-]?key|apikey|api_secret|api_secret_key|secret[_-]?key|auth[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", re.IGNORECASE), Severity.HIGH),
    ("supabase-service-key", re.compile(r"(eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*|sbp_[a-zA-Z0-9]{40,})", re.IGNORECASE), Severity.CRITICAL),
    ("openai-key", re.compile(r"sk-[a-zA-Z0-9]{20,}", re.IGNORECASE), Severity.CRITICAL),
    ("stripe-key", re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24,}", re.IGNORECASE), Severity.CRITICAL),
    ("password-in-code", re.compile(r"password\s*[:=]\s*['\"][^'\"]{4,}['\"]", re.IGNORECASE), Severity.HIGH),
    ("url-with-credentials", re.compile(r"https?://[^:]+:[^@]+@[^\s\"']+", re.IGNORECASE), Severity.HIGH),
]


SQL_INJECTION_HINTS = [
    re.compile(r"\.query\s*\(\s*[^,)]*%s", re.IGNORECASE),
    re.compile(r"execute\s*\(\s*['\"].*%s", re.IGNORECASE),
    re.compile(r"\.raw\s*\(\s*['\"].*%s", re.IGNORECASE),
]


class BaseScanner:
    module = "base"

    def __init__(self, repo: Path):
        self.repo = repo
        self.findings: list[Finding] = []

    def scan(self) -> list[Finding]:
        raise NotImplementedError

    def add(self, rule: str, severity: Severity, file: Path, line: int, message: str, suggestion: str = "", confidence: str = "medium", fixable: bool = False, auto_fix: str = "", column: int = 0):
        self.findings.append(Finding(
            rule=f"{self.module}:{rule}",
            module=self.module,
            severity=severity,
            file=file.relative_to(self.repo) if file.is_absolute() else file,
            line=line,
            column=column,
            message=message,
            suggestion=suggestion,
            confidence=confidence,
            fixable=fixable,
            auto_fix=auto_fix,
        ))

    def score(self, max_score: float = 100.0) -> float:
        if not self.findings:
            return max_score
        weights = {Severity.CRITICAL: 40, Severity.HIGH: 20, Severity.MEDIUM: 10, Severity.LOW: 3, Severity.INFO: 1}
        penalty = sum(weights.get(f.severity, 0) for f in self.findings)
        return max(0.0, max_score - penalty)

    def iter_source_files(self, extensions: tuple[str, ...]) -> list[Path]:
        files = []
        for ext in extensions:
            files.extend(self.repo.rglob(f"*{ext}"))
        return [p for p in files if "node_modules" not in p.parts and ".git" not in p.parts and "__pycache__" not in p.parts and not p.name.endswith(".d.ts")]


def normalize_line(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def is_test_or_fixture(path: Path) -> bool:
    name = path.name.lower()
    parts = [p.lower() for p in path.parts]
    return "test" in parts or "tests" in parts or "fixture" in parts or "fixtures" in parts or name.startswith("test_") or ".test." in name or ".spec." in name


def is_config_file(path: Path) -> bool:
    return path.name.lower() in {"dockerfile", "docker-compose.yml", "docker-compose.yaml", "nginx.conf", ".env.example", ".env.local", ".env.production"}


def is_likely_client_file(path: Path) -> bool:
    parts = set(p.lower() for p in path.parts)
    return bool(parts & {"components", "pages", "app", "src", "client", "frontend", "ui"})
