"""Base scanner utilities and shared helpers."""

import fnmatch
import re
from pathlib import Path

from vibe_coding_qa import Finding, Severity


SECRET_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE(?:\s+)KEY-----", re.IGNORECASE), Severity.CRITICAL),
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL),
    ("generic-api-key", re.compile(r"(?<!\w)(api[_-]?key|apikey|api_secret|api_secret_key|secret[_-]?key|auth[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", re.IGNORECASE), Severity.HIGH),
    ("supabase-service-key", re.compile(r"(eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*|sbp_[a-zA-Z0-9]{40,})", re.IGNORECASE), Severity.CRITICAL),
    ("openai-key", re.compile(r"sk-[a-zA-Z0-9]{20,}", re.IGNORECASE), Severity.CRITICAL),
    ("stripe-key", re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24,}", re.IGNORECASE), Severity.CRITICAL),
    ("password-in-code", re.compile(r"password\s*[:=]\s*['\"][^'\"]{4,}['\"]", re.IGNORECASE), Severity.HIGH),
    ("url-with-credentials", re.compile(r"https?://[^\s:/\"']+:[^\s@/\"']+@[^\s\"']+", re.IGNORECASE), Severity.HIGH),
    # Additional secret patterns for better coverage
    ("jwt-token", re.compile(r"eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"), Severity.CRITICAL),
    ("bearer-token", re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-]{20,}"), Severity.HIGH),
    ("database-url", re.compile(r"(?i)(postgres|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[^\s\"']+"), Severity.CRITICAL),
    ("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), Severity.CRITICAL),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), Severity.HIGH),
    ("sendgrid-key", re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"), Severity.CRITICAL),
    ("twilio-key", re.compile(r"SK[0-9a-f]{32}"), Severity.CRITICAL),
    ("heroku-key", re.compile(r"\bheroku[_-]?(?:api[_-]?)?(?:key|token)\s*['\"]?\s*[:=]\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE), Severity.HIGH),
    ("private-key-pem", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE(?:\s+)KEY-----", re.IGNORECASE), Severity.CRITICAL),
    ("ssh-private-key", re.compile(r"-----BEGIN OPENSSH PRIVATE(?:\s+)KEY-----", re.IGNORECASE), Severity.CRITICAL),
    ("pgp-private-key", re.compile(r"-----BEGIN PGP PRIVATE(?:\s+)KEY BLOCK-----", re.IGNORECASE), Severity.CRITICAL),
]


_PEM_BLOCK_PATTERNS = [
    re.compile(r"-----BEGIN (?P<label>(?:[A-Z0-9]+ )*PRIVATE(?:\s+)KEY)-----[\s\S]*?-----END (?P=label)-----", re.IGNORECASE),
    re.compile(r"-----BEGIN PGP PRIVATE(?:\s+)KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE(?:\s+)KEY BLOCK-----", re.IGNORECASE),
]
_SECRET_REDACTION_PATTERNS = _PEM_BLOCK_PATTERNS + [p for _, p, _ in SECRET_PATTERNS]


def redact_secrets(text: str) -> str:
    """Redact known credentials and complete private-key blocks."""
    for pattern in _SECRET_REDACTION_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def is_secret_finding(finding: Finding) -> bool:
    """Check if a finding is related to exposed secrets."""
    secret_rules = {
        "private-key", "aws-access-key", "generic-api-key", "supabase-service-key",
        "openai-key", "stripe-key", "password-in-code", "url-with-credentials",
        "client-side-secret", "committed-env-file", "session-secret-hardcoded",
        "jwt-token", "bearer-token", "database-url", "github-token",
        "slack-token", "sendgrid-key", "twilio-key", "heroku-key",
        "private-key-pem", "ssh-private-key", "pgp-private-key",
    }
    return finding.rule.split(":")[-1] in secret_rules


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
        ignore = load_ignore_patterns(self.repo)
        return [
            p for p in files
            if "node_modules" not in p.parts
            and ".git" not in p.parts
            and "__pycache__" not in p.parts
            and not p.name.endswith(".d.ts")
            and not is_ignored(p, self.repo, ignore)
        ]


def load_ignore_patterns(repo: Path) -> list[str]:
    patterns: list[str] = []
    ignore_file = repo / ".vcqaignore"
    if ignore_file.is_file():
        for line in ignore_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    return patterns


def is_ignored(path: Path, repo: Path, patterns: list[str] | None = None) -> bool:
    if patterns is None:
        patterns = load_ignore_patterns(repo)
    try:
        rel = path.relative_to(repo).as_posix()
    except ValueError:
        return False
    parts = Path(rel).parts
    for pattern in patterns:
        pat = pattern.rstrip("/")
        # Match exact file or directory name anywhere in the path.
        if pat in parts:
            return True
        # Match full relative path or glob.
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(rel, f"**/{pattern}"):
            return True
        # Match directory prefix.
        if rel.startswith(pat + "/"):
            return True
    return False


def normalize_line(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def is_test_or_fixture(path: Path) -> bool:
    name = path.name.lower()
    parts = [p.lower() for p in path.parts]
    return "test" in parts or "tests" in parts or "fixture" in parts or "fixtures" in parts or name.startswith("test_") or ".test." in name or ".spec." in name


def is_config_file(path: Path) -> bool:
    return path.name.lower() in {"dockerfile", "docker-compose.yml", "docker-compose.yaml", "nginx.conf", ".env.example", ".env.local", ".env.production"}


def is_likely_client_file(path: Path, repo: Path | None = None) -> bool:
    try:
        relative = path.relative_to(repo) if repo else path
    except ValueError:
        relative = path
    parts = [part.lower() for part in relative.parts]
    name = path.name.lower()
    if path.suffix.lower() not in {".ts", ".tsx", ".js", ".jsx", ".vue", ".svelte"}:
        return False
    if set(parts[:-1]) & {"api", "server", "backend", "functions", "middleware"}:
        return False
    if name.startswith("middleware.") or ".server." in name or name.startswith("server."):
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    if re.search(r"(?m)^\s*['\"]use server['\"]\s*;?", text) or re.search(r"\bimport\s+['\"]server-only['\"]", text):
        return False
    if re.search(r"(?m)^\s*['\"]use client['\"]\s*;?", text):
        return True
    if set(parts[:-1]) & {"client", "frontend", "components", "ui"} or name.startswith("client.") or ".client." in name:
        return True
    if "src" in parts[:-1] and repo:
        package_file = repo / "package.json"
        try:
            if re.search(r'"next"\s*:', package_file.read_text(encoding="utf-8", errors="ignore")):
                return False
        except OSError:
            pass
        return True
    if "pages" in parts[:-1]:
        return not re.search(r"\b(getServerSideProps|getStaticProps|apiResolver)\b", text)
    return False
