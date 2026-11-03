"""Database scanner: migrations, RLS, raw SQL, role/privilege fields."""

import re
from pathlib import Path

from . import BaseScanner, load_ignore_patterns, is_ignored, normalize_line
from vibe_coding_qa import Finding, Severity


class DatabaseScanner(BaseScanner):
    module = "database"

    def scan(self) -> list[Finding]:
        ignore = load_ignore_patterns(self.repo)
        sql_files = [p for p in self.repo.rglob("*.sql") if not is_ignored(p, self.repo, ignore)]
        sql_files.sort(key=lambda path: path.as_posix().lower())
        self.tables: dict[str, tuple[Path, int]] = {}
        self.rls_tables: set[str] = set()
        self.policies: dict[str, list[tuple[Path, int, str, str]]] = {}
        for path in sql_files:
            self._scan_sql(path)
        self._check_rls_state()
        for path in self.iter_source_files((".ts", ".tsx", ".js", ".jsx", ".py", ".prisma")):
            self._scan_orm(path)
        return self.findings

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
        for i, raw in self._statements(text):
            norm = normalize_line(raw)

            # Match CREATE TABLE with optional schema qualification
            create = re.search(
                r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?:([a-zA-Z_][a-zA-Z0-9_]*)\.)?([a-zA-Z_][a-zA-Z0-9_]*)",
                norm, re.IGNORECASE
            )
            if create:
                schema = create.group(1).lower() if create.group(1) else "public"
                table = create.group(2).lower()
                fq_table = f"{schema}.{table}"
                self.tables.setdefault(fq_table, (path, i))

            drop_table = re.search(
                r"drop\s+table\s+(?:if\s+exists\s+)?(?:([a-zA-Z_][a-zA-Z0-9_]*)\.)?([a-zA-Z_][a-zA-Z0-9_]*)",
                norm, re.IGNORECASE
            )
            if drop_table:
                schema = drop_table.group(1).lower() if drop_table.group(1) else "public"
                table = drop_table.group(2).lower()
                fq_table = f"{schema}.{table}"
                self.tables.pop(fq_table, None)
                self.rls_tables.discard(fq_table)
                self.policies.pop(fq_table, None)

            # Match ALTER TABLE ... ENABLE ROW LEVEL SECURITY
            if re.search(r"alter\s+table\s+.*enable\s+row\s+level\s+security", norm, re.IGNORECASE):
                table_match = re.search(
                    r"alter\s+table\s+(?:([a-zA-Z_][a-zA-Z0-9_]*)\.)?([a-zA-Z_][a-zA-Z0-9_]*)",
                    norm, re.IGNORECASE
                )
                if table_match:
                    schema = table_match.group(1).lower() if table_match.group(1) else "public"
                    table = table_match.group(2).lower()
                    self.rls_tables.add(f"{schema}.{table}")
            elif re.search(r"alter\s+table\s+.*disable\s+row\s+level\s+security", norm, re.IGNORECASE):
                table_match = re.search(
                    r"alter\s+table\s+(?:([a-zA-Z_][a-zA-Z0-9_]*)\.)?([a-zA-Z_][a-zA-Z0-9_]*)",
                    norm, re.IGNORECASE
                )
                if table_match:
                    schema = table_match.group(1).lower() if table_match.group(1) else "public"
                    table = table_match.group(2).lower()
                    self.rls_tables.discard(f"{schema}.{table}")

            drop_policy = re.search(
                r"drop\s+policy\s+(?:if\s+exists\s+)?(\S+)\s+on\s+(?:([a-zA-Z_][a-zA-Z0-9_]*)\.)?([a-zA-Z_][a-zA-Z0-9_]*)",
                norm, re.IGNORECASE
            )
            if drop_policy:
                policy_name = drop_policy.group(1).strip('"').lower()
                schema = drop_policy.group(2).lower() if drop_policy.group(2) else "public"
                table = drop_policy.group(3).lower()
                fq_table = f"{schema}.{table}"
                remaining = [
                    item for item in self.policies.get(fq_table, [])
                    if item[3].strip('"').lower() != policy_name
                ]
                if remaining:
                    self.policies[fq_table] = remaining
                else:
                    self.policies.pop(fq_table, None)

            # Match CREATE POLICY with optional schema qualification
            policy = re.search(
                r"create\s+policy\s+(\S+)\s+on\s+(?:([a-zA-Z_][a-zA-Z0-9_]*)\.)?([a-zA-Z_][a-zA-Z0-9_]*)(?:\s+for\s+(?:all|select|insert|update|delete))?",
                norm, re.IGNORECASE
            )
            if policy:
                policy_name = policy.group(1).strip('"')
                schema = policy.group(2).lower() if policy.group(2) else "public"
                table = policy.group(3).lower()
                fq_table = f"{schema}.{table}"
                latest = [
                    item for item in self.policies.get(fq_table, [])
                    if item[3].strip('"').lower() != policy_name.lower()
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
                if re.search(r"\bto\s+", norm_lower) is None:
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
