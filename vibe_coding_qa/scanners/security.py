"""Security scanner: secrets, auth, RLS, injection, client/server boundaries."""

import re
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
        self._scan_supabase_rls()
        self._scan_env_files()
        self._scan_firebase_rules()
        return self.findings

    def _scan_for_secrets(self, path: Path) -> None:
        # Test and fixture files frequently contain fake sample secrets; skip them to reduce noise.
        if is_test_or_fixture(path):
            return
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for i, raw in enumerate(lines, 1):
            line = raw.strip()
            if line.startswith("//") or line.startswith("#"):
                # Reduce noise for example comments, but still flag private keys.
                if "PRIVATE KEY" not in line.upper():
                    continue
            for rule, pattern, severity in SECRET_PATTERNS:
                for match in pattern.finditer(raw):
                    if is_test_or_fixture(path) and severity != Severity.CRITICAL:
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
        if not is_likely_client_file(path):
            return
        text = path.read_text(encoding="utf-8", errors="ignore")
        for i, raw in enumerate(text.splitlines(), 1):
            for rule, pattern, severity in SECRET_PATTERNS:
                if severity != Severity.CRITICAL:
                    continue
                for match in pattern.finditer(raw):
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
        if not sql_files and not (self.repo / "supabase").is_dir():
            return
        rls_enabled_tables: set[str] = set()
        tables_seen: set[str] = set()
        for path in sql_files:
            text = path.read_text(encoding="utf-8", errors="ignore")
            for i, raw in enumerate(text.splitlines(), 1):
                norm = normalize_line(raw)
                create_match = re.search(r"create\s+table\s+(?:if\s+not\s+exists\s+)?([a-zA-Z_][a-zA-Z0-9_]*)", norm, re.IGNORECASE)
                if create_match:
                    tables_seen.add(create_match.group(1).lower())
                if re.search(r"alter\s+table\s+.*enable\s+row\s+level\s+security", norm, re.IGNORECASE):
                    table_match = re.search(r"alter\s+table\s+([a-zA-Z_][a-zA-Z0-9_]*)", norm, re.IGNORECASE)
                    if table_match:
                        rls_enabled_tables.add(table_match.group(1).lower())
                if re.search(r"create\s+policy\s+.*on\s+([a-zA-Z_][a-zA-Z0-9_]*)", norm, re.IGNORECASE):
                    policy_match = re.search(r"create\s+policy\s+.*on\s+([a-zA-Z_][a-zA-Z0-9_]*)", norm, re.IGNORECASE)
                    if policy_match:
                        rls_enabled_tables.add(policy_match.group(1).lower())
        for table in tables_seen:
            if table not in rls_enabled_tables:
                self.add(
                    rule="missing-rls",
                    severity=Severity.CRITICAL,
                    file=sql_files[0] if sql_files else self.repo / "supabase",
                    line=1,
                    message=f"Table '{table}' does not appear to have Row Level Security (RLS) enabled or policies defined.",
                    suggestion="Enable RLS on every table and write explicit policies with auth checks.",
                    confidence="medium",
                )

    def _scan_env_files(self) -> None:
        ignore = load_ignore_patterns(self.repo)
        for path in self.repo.rglob(".env*"):
            if is_ignored(path, self.repo, ignore):
                continue
            if path.name == ".env.example":
                continue
            self.add(
                rule="committed-env-file",
                severity=Severity.HIGH,
                file=path,
                line=1,
                message=f"{path.name} is committed to the repository; environment files should not be tracked.",
                suggestion="Remove the file from git, add it to .gitignore, and rotate any exposed secrets.",
                confidence="high",
            )

    def _scan_for_insecure_uploads(self, path: Path) -> None:
        if path.suffix not in {".ts", ".js", ".py"}:
            return
        text = path.read_text(encoding="utf-8", errors="ignore")
        for i, raw in enumerate(text.splitlines(), 1):
            if re.search(r"(multer|upload|busboy|formidable|receive|save).*?file", raw, re.IGNORECASE):
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
            if re.search(r"res\.cookie\s*\(|set-cookie|cookie\s*\(", raw, re.IGNORECASE):
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
