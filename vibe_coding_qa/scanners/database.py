"""Database scanner: migrations, RLS, raw SQL, role/privilege fields."""

import re
from pathlib import Path

from . import BaseScanner, load_ignore_patterns, is_ignored, normalize_line
from vibe_coding_qa import Finding, Severity


# Optional dependency. pglast provides a real PostgreSQL parser, but it is a
# compiled, heavyweight dependency, so it is NOT required. When present it is
# used only to validate that migrations parse; RLS extraction stays on the
# conservative pattern matcher below and never claims to be a full parser.
try:  # pragma: no cover - depends on the optional extra being installed
    import pglast  # type: ignore

    _PGLAST_AVAILABLE = True
except Exception:  # pragma: no cover
    pglast = None  # type: ignore
    _PGLAST_AVAILABLE = False


# A PostgreSQL identifier: either a quoted identifier (with doubled quotes) or a
# bare identifier. Two capture groups follow: optional schema, then table name.
_IDENT = r'(?:"(?:[^"]|"")*"|[A-Za-z_][A-Za-z0-9_$]*)'
_SCHEMA_TABLE = rf'(?:({_IDENT})\s*\.\s*)?({_IDENT})'


class DatabaseScanner(BaseScanner):
    module = "database"

    def scan(self) -> list[Finding]:
        self.notes: list[str] = [
            "Row Level Security analysis matches migration statements with pattern matching; "
            "it is a conservative heuristic, not a full PostgreSQL parser.",
        ]
        if not _PGLAST_AVAILABLE:
            self.notes.append(
                "Optional 'pglast' dependency is not installed; unusual SQL constructs may not be "
                "recognized. Install it for stricter statement validation."
            )
        ignore = load_ignore_patterns(self.repo)
        sql_files = [p for p in self.repo.rglob("*.sql") if not is_ignored(p, self.repo, ignore)]
        sql_files.sort(key=lambda path: path.as_posix().lower())
        if not sql_files:
            self.notes.append("No SQL migration files were found; database RLS analysis was skipped.")
        self.tables: dict[str, tuple[Path, int]] = {}
        self.rls_tables: set[str] = set()
        self.policies: dict[str, list[tuple[Path, int, str, str]]] = {}
        self._unsafe_files: set[Path] = set()
        for path in sql_files:
            self._scan_sql(path)
        if self._unsafe_files:
            names = ", ".join(sorted(p.name for p in self._unsafe_files))
            self.notes.append(
                f"Dynamic SQL or procedural blocks were detected in: {names}. RLS state for those "
                "constructs cannot be determined by static pattern matching and requires manual review."
            )
        self._check_rls_state()
        for path in self.iter_source_files((".ts", ".tsx", ".js", ".jsx", ".py", ".prisma")):
            self._scan_orm(path)
        return self.findings

    @staticmethod
    def _identifier(raw: str) -> str:
        """Normalize a matched identifier using PostgreSQL folding rules.

        Quoted identifiers keep their case and have doubled quotes collapsed;
        unquoted identifiers fold to lower case.
        """
        raw = raw.strip()
        if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
            return raw[1:-1].replace('""', '"')
        return raw.lower()

    @classmethod
    def _qualified(cls, schema: str | None, table: str) -> str:
        schema_name = cls._identifier(schema) if schema else "public"
        return f"{schema_name}.{cls._identifier(table)}"


    @staticmethod
    def _statements(text: str):
        pending: list[str] = []
        start_line = 1
        for line_number, raw in enumerate(text.splitlines(), 1):
            if raw.lstrip().startswith("--"):
                continue
            parts = raw.split(";")
            for part_index, part in enumerate(parts):
                if not pending and part.strip():
                    start_line = line_number
                pending.append(part)
                if part_index < len(parts) - 1:
                    statement = normalize_line(" ".join(pending))
                    if statement:
                        yield start_line, statement
                    pending = []
        if pending:
            statement = normalize_line(" ".join(pending))
            if statement:
                yield start_line, statement

    def _scan_sql(self, path: Path) -> None:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if self._has_unsupported_construct(text):
            self._unsafe_files.add(path)
        if _PGLAST_AVAILABLE:  # pragma: no cover - optional dependency
            try:
                pglast.parse_sql(text)
            except Exception:
                self.notes.append(
                    f"pglast could not parse {path.name}; RLS coverage for this file may be incomplete."
                )
        for i, raw in self._statements(text):
            norm = normalize_line(raw)

            # Match CREATE TABLE with optional schema qualifier and quoted identifiers.
            create = re.search(
                rf"create\s+table\s+(?:if\s+not\s+exists\s+)?(?:only\s+)?{_SCHEMA_TABLE}",
                norm, re.IGNORECASE | re.DOTALL
            )
            if create:
                fq_table = self._qualified(create.group(1), create.group(2))
                self.tables.setdefault(fq_table, (path, i))

            drop_table = re.search(
                rf"drop\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?{_SCHEMA_TABLE}",
                norm, re.IGNORECASE | re.DOTALL
            )
            if drop_table:
                fq_table = self._qualified(drop_table.group(1), drop_table.group(2))
                self.tables.pop(fq_table, None)
                self.rls_tables.discard(fq_table)
                self.policies.pop(fq_table, None)

            # ALTER TABLE ... [ENABLE|DISABLE] ROW LEVEL SECURITY (FORCE is recorded but
            # does not by itself enable RLS, so it is intentionally not treated as enable).
            alter = re.search(
                rf"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?{_SCHEMA_TABLE}\s+(enable|disable|force)\s+row\s+level\s+security",
                norm, re.IGNORECASE | re.DOTALL
            )
            if alter:
                fq_table = self._qualified(alter.group(1), alter.group(2))
                action = alter.group(3).lower()
                if action == "enable":
                    self.rls_tables.add(fq_table)
                elif action == "disable":
                    self.rls_tables.discard(fq_table)

            drop_policy = re.search(
                rf"drop\s+policy\s+(?:if\s+exists\s+)?({_IDENT})\s+on\s+{_SCHEMA_TABLE}",
                norm, re.IGNORECASE | re.DOTALL
            )
            if drop_policy:
                policy_name = self._identifier(drop_policy.group(1))
                fq_table = self._qualified(drop_policy.group(2), drop_policy.group(3))
                remaining = [
                    item for item in self.policies.get(fq_table, [])
                    if item[3].lower() != policy_name.lower()
                ]
                if remaining:
                    self.policies[fq_table] = remaining
                else:
                    self.policies.pop(fq_table, None)

            # Match CREATE POLICY with optional schema qualifier; the full normalized
            # statement is stored so USING / WITH CHECK / TO clauses can be inspected.
            policy = re.search(
                rf"create\s+policy\s+({_IDENT})\s+on\s+{_SCHEMA_TABLE}",
                norm, re.IGNORECASE | re.DOTALL
            )
            if policy:
                policy_name = self._identifier(policy.group(1))
                fq_table = self._qualified(policy.group(2), policy.group(3))
                latest = [
                    item for item in self.policies.get(fq_table, [])
                    if item[3].lower() != policy_name.lower()
                ]
                latest.append((path, i, norm, policy_name))
                self.policies[fq_table] = latest

            # Check for editable role fields
            if re.search(r"role\s*=\s*['\"]?(admin|user|editor)['\"]?", raw, re.IGNORECASE) and "set" in norm.lower():
                self.add(
                    rule="editable-role-field",
                    severity=Severity.CRITICAL,
                    file=path,
                    line=i,
                    message="SQL appears to allow direct role assignment without server-side gate.",
                    suggestion="Role changes must be handled by a privileged server function, not exposed in user update paths.",
                    confidence="low",
                )

    @staticmethod
    def _has_unsupported_construct(text: str) -> bool:
        """Detect procedural/dynamic SQL the pattern matcher cannot reason about."""
        return bool(re.search(
            r"(\bdo\s+\$|\bexecute\s+(?:format\s*\()|\$\$|\blanguage\s+plpgsql\b|"
            r"\bsecurity\s+definer\b|\bcreate\s+(?:or\s+replace\s+)?function\b)",
            text, re.IGNORECASE,
        ))

    def _check_rls_state(self) -> None:
        policies_by_table = self.policies
        for table, (path, line) in self.tables.items():
            if table not in self.rls_tables:
                if table in policies_by_table:
                    policy_path, policy_line, _, _ = policies_by_table[table][0]
                    self.add(
                        rule="policy-without-rls-enabled",
                        severity=Severity.CRITICAL,
                        file=policy_path,
                        line=policy_line,
                        message=f"Table '{table}' has policies but Row Level Security is not enabled. Policies have no effect until RLS is enabled.",
                        suggestion=f"Add 'ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;' for this table.",
                        confidence="high",
                    )
                else:
                    self.add(
                        rule="table-without-rls",
                        severity=Severity.CRITICAL,
                        file=path,
                        line=line,
                        message=f"Table '{table}' has no Row Level Security policy.",
                        suggestion="Enable RLS and create explicit policies that check the requesting user.",
                        confidence="medium",
                    )
            elif table not in policies_by_table:
                self.add(
                    rule="rls-enabled-without-policy",
                    severity=Severity.MEDIUM,
                    file=path,
                    line=line,
                    message=f"Table '{table}' has RLS enabled but no policy was found in scanned migrations; access may be intentionally denied by default.",
                    suggestion="Confirm deny-all behavior is intentional or add least-privilege policies.",
                    confidence="medium",
                )

        for table, entries in policies_by_table.items():
            for path, line, norm, policy_name in entries:
                norm_lower = norm.lower()
                if "using" not in norm_lower and "with check" not in norm_lower:
                    self.add(
                        rule="rls-policy-missing-condition",
                        severity=Severity.HIGH,
                        file=path,
                        line=line,
                        message=f"RLS policy '{policy_name}' on '{table}' lacks a USING or WITH CHECK condition.",
                        suggestion="Add explicit row predicates appropriate to the permitted operation.",
                        confidence="medium",
                    )
                if re.search(r"using\s*\(\s*true\s*\)", norm_lower) or re.search(r"with\s+check\s*\(\s*true\s*\)", norm_lower):
                    self.add(
                        rule="rls-policy-overly-permissive",
                        severity=Severity.HIGH,
                        file=path,
                        line=line,
                        message=f"RLS policy '{policy_name}' on '{table}' uses a true condition, allowing unrestricted access for its operation.",
                        suggestion="Replace true with a restrictive ownership or role predicate.",
                        confidence="high",
                    )
                has_role_clause = bool(re.search(
                    r"\bto\s+(?:group\s+)?(?:\"[^\"]+\"|[a-z_][a-z0-9_]*|public|current_user|session_user)",
                    norm_lower,
                ))
                if not has_role_clause:
                    self.add(
                        rule="rls-policy-missing-role-restriction",
                        severity=Severity.MEDIUM,
                        file=path,
                        line=line,
                        message=f"RLS policy '{policy_name}' on '{table}' does not declare an allowed role; PostgreSQL policies default to PUBLIC.",
                        suggestion="Add a suitable TO role clause and verify that the predicate enforces the intended access boundary.",
                        confidence="medium",
                    )

    def _scan_orm(self, path: Path) -> None:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for i, raw in enumerate(text.splitlines(), 1):
            if path.suffix == ".prisma":
                if re.search(r"^\s*model\s+\w+", raw):
                    model = re.search(r"model\s+(\w+)", raw).group(1)
                    # Prisma models cannot express RLS natively; flag for review.
                    self.add(
                        rule="prisma-model-rls-review",
                        severity=Severity.MEDIUM,
                        file=path,
                        line=i,
                        message=f"Prisma model '{model}' cannot enforce RLS at the database layer automatically.",
                        suggestion="Implement authorization checks in every query path or move access control to a database with native RLS.",
                        confidence="medium",
                    )
            if re.search(r"\.update\s*\(\s*\{[^}]*role", raw, re.IGNORECASE):
                self.add(
                    rule="client-role-update",
                    severity=Severity.CRITICAL,
                    file=path,
                    line=i,
                    message="Client code may allow a user to update their own role field.",
                    suggestion="Strip role/privilege fields from public update payloads and restrict role changes to server-side admin logic.",
                    confidence="medium",
                )
            if re.search(r"(supabase|db)\.from\s*\(\s*['\"][^'\"]+['\"]\s*\)\.(select|insert|update|delete)\s*\(", raw, re.IGNORECASE):
                if i < len(text.splitlines()):
                    next_lines = "\n".join(text.splitlines()[i:i + 8])
                    if "auth" not in next_lines.lower() and "rls" not in next_lines.lower():
                        self.add(
                            rule="supabase-query-auth-review",
                            severity=Severity.MEDIUM,
                            file=path,
                            line=i,
                            message="Supabase query without visible auth check; relies on RLS being configured.",
                            suggestion="Verify RLS policies exist for this table, or add an explicit server-side auth check.",
                            confidence="low",
                        )
