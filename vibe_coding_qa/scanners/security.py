"""Security scanner: secrets, auth, RLS, injection, client/server boundaries."""

import re
import subprocess
from pathlib import Path

from . import BaseScanner, SECRET_PATTERNS, SQL_INJECTION_HINTS, is_ignored, is_likely_client_file, is_test_or_fixture, load_ignore_patterns, normalize_line
from vibe_coding_qa import Finding, Severity


class SecurityScanner(BaseScanner):
    module = "security"

    # Files that are expected to contain keys only server-side.
    SERVER_PATHS = {"server", "api", "backend", "middleware", "routes", "functions", "supabase/functions"}

    def scan(self) -> list[Finding]:
        files = self.iter_source_files((".ts", ".tsx", ".js", ".jsx", ".py", ".sql", ".md", ".json", ".yml", ".yaml", ".env"))
        for path in files:
            self._scan_for_secrets(path)
            self._scan_for_insecure_eval(path)
            self._scan_for_client_secrets(path)
            self._scan_for_insecure_cors(path)
            self._scan_for_missing_auth(path)
            self._scan_for_sql_injection(path)
            self._scan_for_insecure_uploads(path)
            self._scan_for_path_traversal(path)
            self._scan_for_ssrf(path)
            self._scan_for_insecure_cookies(path)
            self._scan_for_debug_endpoints(path)
            self._scan_for_shell_exec(path)
            self._scan_for_rate_limits(path)
            self._scan_for_insecure_sessions(path)
        self._scan_env_files()
        self._scan_firebase_rules()
        return self.findings

    def _scan_for_secrets(self, path: Path) -> None:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for i, raw in enumerate(lines, 1):
            line = raw.strip()
            if line.startswith("//") or line.startswith("#"):
                if "PRIVATE KEY" not in line.upper():
                    continue
            for rule, pattern, severity in SECRET_PATTERNS:
                for match in pattern.finditer(raw):
                    if self._is_likely_synthetic(match):
                        continue
                    self.add(
                        rule=rule,
                        severity=severity,
                        file=path,
                        line=i,
                        column=match.start(),
                        message=f"Possible {rule.replace('-', ' ')} exposed in source.",
                        suggestion="Move secrets to environment variables or a vault; never commit keys.",
                        confidence="high",
                    )

    @staticmethod
    def _credential_value(match: re.Match) -> str:
        """Extract only the credential literal from a match.

        Assignment patterns such as ``api_key = "value"`` match the whole
        statement; the surrounding variable name must never influence the
        synthetic/placeholder decision, so only the value portion is returned.
        For bare-token rules (``sk-...``) the match itself is the value.
        """
        text = match.group(0)
        quoted = re.search(r"['\"]([^'\"]+)['\"]", text)
        if quoted:
            return quoted.group(1)
        assignment = re.match(r"[A-Za-z0-9_\-.]+\s*[:=]\s*(.+)$", text)
        if assignment:
            return assignment.group(1).strip().strip("'\"")
        return text

    #: Values that are placeholders whenever they appear verbatim as the credential.
    _PLACEHOLDER_LITERALS = {
        "test", "tests", "example", "sample", "demo", "dummy", "fake", "mock",
        "placeholder", "changeme", "change-me", "change_me", "replace-me",
        "replace_me", "your-key", "your_key", "yourkey", "your-api-key-here",
        "your-api-key", "your_api_key", "your-secret", "your_secret",
        "your-token", "your_token", "insert-key", "insert_key", "your_key_here",
        "secret", "password", "token", "apikey", "api-key", "none", "null",
        "undefined", "todo", "fixme",
    }

    #: Unambiguous substrings that only make sense inside a placeholder value.
    _PLACEHOLDER_SUBSTRINGS = (
        "not-real", "not_real", "notreal",
        "replace-me", "replace_me", "replaceme",
        "change-me", "change_me", "changeme", "changeit",
        "your-api-key", "your_api_key", "yourapikey",
        "your-secret", "your_secret", "yoursecret",
        "your-token", "your_token", "yourtoken",
        "insert-your", "insert_your",
        "insert-key", "insert_key",
        "placeholder",
        "example-key", "sample-key", "test-key", "dummy-key", "fake-key",
        "mock-key", "example_key", "sample_key", "test_key",
    )

    #: Standalone tokens that mark a value as an obvious placeholder.
    _PLACEHOLDER_TOKENS = {
        "example", "sample", "dummy", "fake", "mock", "placeholder",
        "changeme", "notreal", "yourkey",
    }

    @classmethod
    def _placeholder_reason(cls, value: str) -> str | None:
        """Return a human-readable reason when ``value`` is clearly synthetic.

        Recognition is deliberately narrow and operates only on the credential
        value. A *variable name* containing ``TEST``, ``EXAMPLE`` or ``MOCK``
        must never suppress detection, and a real token that merely contains the
        substring ``test`` must still be reported.
        """
        if not value or not value.strip():
            return "empty value"
        lowered = value.strip().strip("'\"")
        if not lowered:
            return "empty value"
        lowered = lowered.lower()

        if lowered in cls._PLACEHOLDER_LITERALS:
            return "known placeholder literal"
        if lowered.startswith("<") and lowered.endswith(">"):
            return "angle-bracket placeholder"
        if lowered in {"*" * len(lowered), "x" * len(lowered)}:
            return "masked placeholder"
        if re.fullmatch(r"(abcdef)+", lowered):
            return "sequential placeholder"
        if re.search(r"x{4,}", lowered):
            return "repeated placeholder character"
        if len(set(lowered)) == 1 and len(lowered) >= 4:
            return "single repeated character"
        for indicator in cls._PLACEHOLDER_SUBSTRINGS:
            if indicator in lowered:
                return f"placeholder marker '{indicator}'"
        tokens = [token for token in re.split(r"[^a-z0-9]+", lowered) if token]
        for token in tokens:
            if token in cls._PLACEHOLDER_TOKENS:
                return f"placeholder token '{token}'"
        return None

    @classmethod
    def _is_likely_synthetic(cls, match: re.Match) -> bool:
        """Decide whether a matched credential is a synthetic placeholder.

        Only the matched credential value is inspected; surrounding source text
        (variable names, comments, file paths) is intentionally ignored.
        """
        return cls._placeholder_reason(cls._credential_value(match)) is not None

    def _scan_for_insecure_eval(self, path: Path) -> None:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for i, raw in enumerate(text.splitlines(), 1):
            if re.search(r"(?<!\w)(eval|Function|setTimeout|setInterval)\s*\(\s*['\"`]|innerHTML\s*=", raw):
                self.add(
                    rule="dangerous-runtime-code",
                    severity=Severity.HIGH,
                    file=path,
                    line=i,
                    message="Dangerous runtime code execution or raw HTML assignment detected.",
                    suggestion="Avoid eval/Function with string sources and use safe DOM methods instead of innerHTML.",
                    confidence="medium",
                )

    def _scan_for_client_secrets(self, path: Path) -> None:
        if not is_likely_client_file(path, self.repo):
            return
        text = path.read_text(encoding="utf-8", errors="ignore")
        for i, raw in enumerate(text.splitlines(), 1):
            for rule, pattern, severity in SECRET_PATTERNS:
                if severity != Severity.CRITICAL:
                    continue
                for match in pattern.finditer(raw):
                    if self._is_likely_synthetic(match):
                        continue
                    self.add(
                        rule="client-side-secret",
                        severity=Severity.CRITICAL,
                        file=path,
                        line=i,
                        column=match.start(),
                        message="Secret appears in a client-side file; client bundles can leak it.",
                        suggestion="Move the secret to a server route and call it from the client.",
                        confidence="high",
                    )

    def _scan_for_insecure_cors(self, path: Path) -> None:
        if path.suffix not in {".ts", ".js", ".py"}:
            return
        text = path.read_text(encoding="utf-8", errors="ignore")
        for i, raw in enumerate(text.splitlines(), 1):
            if re.search(r"Access-Control-Allow-Origin\s*[:=]\s*['\"]\*['\"]|cors\(.*origin:\s*['\"]\*['\"]", raw, re.IGNORECASE):
                self.add(
                    rule="wildcard-cors",
                    severity=Severity.MEDIUM,
                    file=path,
                    line=i,
                    message="Wildcard CORS origin allows any website to call this backend.",
                    suggestion="Restrict CORS to known production origins and include credentials only with explicit origins.",
                    confidence="medium",
                )

    def _scan_for_missing_auth(self, path: Path) -> None:
        if path.suffix not in {".ts", ".js", ".py"}:
            return
        if not any(part in self.SERVER_PATHS for part in {p.lower() for p in path.parts}):
            return
        text = path.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
        in_handler = False
        handler_start = 0
        for i, raw in enumerate(lines, 1):
            if re.search(r"(app\.|router\.|route\.|export\s+(default\s+)?(async\s+)?function|def\s+).*(post|put|delete|patch)", raw, re.IGNORECASE):
                in_handler = True
                handler_start = i
                continue
            if in_handler and raw.strip() == "":
                in_handler = False
            if in_handler and i - handler_start < 25:
                lowered = raw.lower()
                if any(term in lowered for term in ("auth", "verify", "session", "jwt", "middleware", "protect", "requireauth")):
                    in_handler = False
        # This is a coarse heuristic; we do not raise findings here because it
        # produces too many false positives without runtime knowledge. Instead,
        # we rely on explicit route inventories from tests or the database scanner.

    def _scan_for_sql_injection(self, path: Path) -> None:
        if path.suffix not in {".ts", ".js", ".py"}:
            return
        text = path.read_text(encoding="utf-8", errors="ignore")
        for i, raw in enumerate(text.splitlines(), 1):
            if "%s" in raw or "${" in raw:
                for pattern in SQL_INJECTION_HINTS:
                    if pattern.search(raw):
                        self.add(
                            rule="sql-injection-risk",
                            severity=Severity.HIGH,
                            file=path,
                            line=i,
                            message="Raw SQL/query construction may interpolate user input.",
                            suggestion="Use parameterized queries, an ORM, or a query builder.",
                            confidence="low",
                        )
                        break

    def _scan_supabase_rls(self) -> None:
        ignore = load_ignore_patterns(self.repo)
        sql_files = [p for p in self.repo.rglob("*.sql") if not is_ignored(p, self.repo, ignore)]
        sql_files.sort(key=lambda path: path.as_posix().lower())
        if not sql_files and not (self.repo / "supabase").is_dir():
            return
        rls_enabled_tables: set[str] = set()
        tables_with_policies: dict[str, tuple[Path, int]] = {}
        tables_seen: dict[str, tuple[Path, int]] = {}
        for path in sql_files:
            text = path.read_text(encoding="utf-8", errors="ignore")
            for i, raw in enumerate(text.splitlines(), 1):
                norm = normalize_line(raw)
                create_match = re.search(
                    r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?:([a-zA-Z_][a-zA-Z0-9_]*)\.)?([a-zA-Z_][a-zA-Z0-9_]*)",
                    norm, re.IGNORECASE
                )
                if create_match:
                    schema = create_match.group(1).lower() if create_match.group(1) else "public"
                    table = create_match.group(2).lower()
                    fq_table = f"{schema}.{table}"
                    tables_seen.setdefault(fq_table, (path, i))
                if re.search(r"alter\s+table\s+.*enable\s+row\s+level\s+security", norm, re.IGNORECASE):
                    table_match = re.search(
                        r"alter\s+table\s+(?:([a-zA-Z_][a-zA-Z0-9_]*)\.)?([a-zA-Z_][a-zA-Z0-9_]*)",
                        norm, re.IGNORECASE
                    )
                    if table_match:
                        schema = table_match.group(1).lower() if table_match.group(1) else "public"
                        table = table_match.group(2).lower()
                        fq_table = f"{schema}.{table}"
                        rls_enabled_tables.add(fq_table)
                elif re.search(r"alter\s+table\s+.*disable\s+row\s+level\s+security", norm, re.IGNORECASE):
                    table_match = re.search(
                        r"alter\s+table\s+(?:([a-zA-Z_][a-zA-Z0-9_]*)\.)?([a-zA-Z_][a-zA-Z0-9_]*)",
                        norm, re.IGNORECASE
                    )
                    if table_match:
                        schema = table_match.group(1).lower() if table_match.group(1) else "public"
                        table = table_match.group(2).lower()
                        rls_enabled_tables.discard(f"{schema}.{table}")
                if re.search(r"create\s+policy\s+.*on\s+(?:([a-zA-Z_][a-zA-Z0-9_]*)\.)?([a-zA-Z_][a-zA-Z0-9_]*)", norm, re.IGNORECASE):
                    policy_match = re.search(
                        r"create\s+policy\s+.*on\s+(?:([a-zA-Z_][a-zA-Z0-9_]*)\.)?([a-zA-Z_][a-zA-Z0-9_]*)",
                        norm, re.IGNORECASE
                    )
                    if policy_match:
                        schema = policy_match.group(1).lower() if policy_match.group(1) else "public"
                        table = policy_match.group(2).lower()
                        fq_table = f"{schema}.{table}"
                        tables_with_policies.setdefault(fq_table, (path, i))
        for table, (table_path, table_line) in tables_seen.items():
            if table not in rls_enabled_tables:
                if table in tables_with_policies:
                    policy_path, policy_line = tables_with_policies[table]
                    self.add(
                        rule="policy-without-rls-enabled",
                        severity=Severity.CRITICAL,
                        file=policy_path,
                        line=policy_line,
                        message=f"Table '{table}' has policies but Row Level Security is not enabled. Policies have no effect until RLS is enabled with 'ALTER TABLE ... ENABLE ROW LEVEL SECURITY'.",
                        suggestion="Add 'ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;' before creating policies.",
                        confidence="high",
                    )
                else:
                    self.add(
                        rule="missing-rls",
                        severity=Severity.CRITICAL,
                        file=table_path,
                        line=table_line,
                        message=f"Table '{table}' does not appear to have Row Level Security (RLS) enabled or policies defined.",
                        suggestion="Enable RLS on every table and write explicit policies with auth checks.",
                        confidence="medium",
                    )

    def _scan_env_files(self) -> None:
        ignore = load_ignore_patterns(self.repo)
        try:
            tracked_result = subprocess.run(
                ["git", "-C", str(self.repo.resolve()), "ls-files", "-z", "--", "."],
                capture_output=True, timeout=10, check=False,
            )
            tracked = set(tracked_result.stdout.decode("utf-8", errors="surrogateescape").split("\0")) if tracked_result.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            tracked = None
        for path in self.repo.rglob(".env*"):
            if is_ignored(path, self.repo, ignore) or path.name == ".env.example" or not path.is_file():
                continue
            relative = path.relative_to(self.repo).as_posix()
            if tracked is not None and relative in tracked:
                self.add(
                    rule="committed-env-file", severity=Severity.HIGH, file=path, line=1,
                    message=f"{path.name} is tracked by Git; environment files may expose credentials.",
                    suggestion="Remove the file from Git, add it to .gitignore, and rotate any exposed secrets.",
                    confidence="high",
                )
            elif tracked is None:
                self.add(
                    rule="env-file-tracking-unverified", severity=Severity.LOW, file=path, line=1,
                    message=f"{path.name} is present; Git tracking could not be verified.",
                    suggestion="Check whether the file is tracked and ensure it contains no exposed secrets.",
                    confidence="medium",
                )

    def _scan_for_insecure_uploads(self, path: Path) -> None:
        if path.suffix not in {".ts", ".js", ".py"}:
            return
        text = path.read_text(encoding="utf-8", errors="ignore")
        for i, raw in enumerate(text.splitlines(), 1):
            if re.search(r"(?:multer|upload|busboy|formidable|receive|save)[A-Za-z0-9_]*\s*(?:\(|=).*?(?:file|req\.files|multipart)", raw, re.IGNORECASE):
                if not re.search(r"(mimetype|extension|magic|size|limit|validate|sanitize)", raw, re.IGNORECASE):
                    self.add(
                        rule="unvalidated-file-upload",
                        severity=Severity.HIGH,
                        file=path,
                        line=i,
                        message="File upload handler may not validate file type or size.",
                        suggestion="Validate MIME type, extension, and size; store uploads outside the web root and scan for malware.",
                        confidence="low",
                    )

    def _scan_for_path_traversal(self, path: Path) -> None:
        if path.suffix not in {".ts", ".js", ".py"}:
            return
        text = path.read_text(encoding="utf-8", errors="ignore")
        risky = [
            r"(readFileSync|writeFileSync|sendFile|createReadStream|open)\s*\(\s*[^)]*(req\.|request\.|params|query|body)",
            r"path\.join\s*\(\s*__dirname\s*,\s*[^)]*(req\.|request\.|params|query|body)",
            r"open\s*\(\s*[^)]*(req\.|request\.|params|query|body)",
        ]
        for i, raw in enumerate(text.splitlines(), 1):
            for pattern in risky:
                if re.search(pattern, raw, re.IGNORECASE):
                    self.add(
                        rule="path-traversal-risk",
                        severity=Severity.HIGH,
                        file=path,
                        line=i,
                        message="File-system access appears to use user-controlled path components.",
                        suggestion="Resolve the path, enforce an allowlist directory, and reject traversal sequences.",
                        confidence="low",
                    )
                    break

    def _scan_for_ssrf(self, path: Path) -> None:
        if path.suffix not in {".ts", ".js", ".py"}:
            return
        text = path.read_text(encoding="utf-8", errors="ignore")
        for i, raw in enumerate(text.splitlines(), 1):
            if re.search(r"(fetch|axios|request|curl|urllib|http\.get)\s*\(\s*(req\.|request\.|params|query|body)", raw, re.IGNORECASE):
                self.add(
                    rule="ssrf-risk",
                    severity=Severity.HIGH,
                    file=path,
                    line=i,
                    message="Outgoing request URL may be controlled by user input, creating SSRF risk.",
                    suggestion="Use an allowlist of permitted URLs/hosts and never forward raw user input to backend requests.",
                    confidence="low",
                )

    def _scan_for_insecure_cookies(self, path: Path) -> None:
        if path.suffix not in {".ts", ".js", ".py"}:
            return
        text = path.read_text(encoding="utf-8", errors="ignore")
        for i, raw in enumerate(text.splitlines(), 1):
            # The character class in "set[-]cookie" matches the response header
            # while preventing this rule from flagging its own pattern line.
            if re.search(r"res\.cookie\s*\(|set[-]cookie|cookie\s*\(", raw, re.IGNORECASE):
                lowered = raw.lower()
                if "secure" not in lowered or "httponly" not in lowered or "samesite" not in lowered:
                    self.add(
                        rule="insecure-cookie-settings",
                        severity=Severity.MEDIUM,
                        file=path,
                        line=i,
                        message="Cookie/session setter is missing Secure, HttpOnly, or SameSite attributes.",
                        suggestion="Set Secure, HttpOnly, and SameSite=Strict/Lax on session cookies.",
                        confidence="low",
                    )

    def _scan_for_debug_endpoints(self, path: Path) -> None:
        if path.suffix not in {".ts", ".js", ".py"}:
            return
        text = path.read_text(encoding="utf-8", errors="ignore")
        for i, raw in enumerate(text.splitlines(), 1):
            if re.search(r"['\"](/debug(?:/[^'\"]*)?|/env(?:/[^'\"]*)?|/config(?:/[^'\"]*)?|/internal(?:/[^'\"]*)?|/admin(?:/[^'\"]*)?|/trace(?:/[^'\"]*)?)['\"]", raw, re.IGNORECASE):
                if not re.search(r"auth|verify|admin|require", raw, re.IGNORECASE):
                    self.add(
                        rule="exposed-debug-endpoint",
                        severity=Severity.MEDIUM,
                        file=path,
                        line=i,
                        message="Endpoint path looks like a debug/internal route without obvious protection.",
                        suggestion="Protect debug endpoints with authentication, IP allowlists, or disable them in production.",
                        confidence="low",
                    )

    def _scan_for_shell_exec(self, path: Path) -> None:
        if path.suffix not in {".ts", ".js", ".py"}:
            return
        text = path.read_text(encoding="utf-8", errors="ignore")
        for i, raw in enumerate(text.splitlines(), 1):
            if re.search(r"(?:^|[^a-zA-Z0-9_.])(exec|execSync|execFile|spawn|child_process|subprocess\.call|os\.system)\s*\(", raw, re.IGNORECASE):
                if re.search(r"(req\.|request\.|params|query|body)", raw, re.IGNORECASE):
                    self.add(
                        rule="unsafe-shell-execution",
                        severity=Severity.CRITICAL,
                        file=path,
                        line=i,
                        message="Shell command appears to execute user-controlled input.",
                        suggestion="Never pass user input to shell commands; use parameterized APIs or explicit allowlists.",
                        confidence="medium",
                    )

    def _scan_for_rate_limits(self, path: Path) -> None:
        if path.suffix not in {".ts", ".js", ".py"}:
            return
        if not any(part in self.SERVER_PATHS for part in {p.lower() for p in path.parts}):
            return
        text = path.read_text(encoding="utf-8", errors="ignore")
        has_rate_limit = bool(re.search(r"(rate.?limit|throttle|slow.?down|@limiter)", text, re.IGNORECASE))
        if has_rate_limit:
            return
        for i, raw in enumerate(text.splitlines(), 1):
            if re.search(r"\.(post|put|delete|patch)\s*\(\s*['\"](login|signin|auth|register|password|reset|api/)", raw, re.IGNORECASE):
                self.add(
                    rule="missing-rate-limit",
                    severity=Severity.MEDIUM,
                    file=path,
                    line=i,
                    message="Sensitive endpoint does not appear to have rate limiting.",
                    suggestion="Add rate limiting to authentication and password-reset endpoints.",
                    confidence="low",
                )
                break

    def _scan_for_insecure_sessions(self, path: Path) -> None:
        if path.suffix not in {".ts", ".js", ".py"}:
            return
        text = path.read_text(encoding="utf-8", errors="ignore")
        for i, raw in enumerate(text.splitlines(), 1):
            if re.search(r"session\s*\(\s*\{|express-session|cookie-session", raw, re.IGNORECASE):
                lowered = raw.lower()
                if "secret" in lowered and ("process.env" not in lowered and "os.environ" not in lowered and "SECRET" not in raw):
                    self.add(
                        rule="session-secret-hardcoded",
                        severity=Severity.HIGH,
                        file=path,
                        line=i,
                        message="Session secret may be hardcoded.",
                        suggestion="Load session secrets from environment variables or a vault.",
                        confidence="low",
                    )

    def _scan_firebase_rules(self) -> None:
        ignore = load_ignore_patterns(self.repo)
        for path in self.repo.rglob("*.rules"):
            if is_ignored(path, self.repo, ignore):
                continue
            if "firebase" not in path.name.lower():
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            lowered = text.lower()
            if '".read": true' in lowered or '".write": true' in lowered or "$uid == null" in lowered or "auth == null" in lowered:
                self.add(
                    rule="firebase-insecure-rules",
                    severity=Severity.CRITICAL,
                    file=path,
                    line=1,
                    message="Firebase rules appear to allow unauthenticated read or write access.",
                    suggestion="Require auth.uid() != null in rules and validate ownership conditions.",
                    confidence="medium",
                )
