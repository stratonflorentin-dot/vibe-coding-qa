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
        for path in sql_files:
            self._scan_sql(path)
        for path in self.iter_source_files((".ts", ".tsx", ".js", ".jsx", ".py", ".prisma")):
            self._scan_orm(path)
        return self.findings

    def _scan_sql(self, path: Path) -> None:
        text = path.read_text(encoding="utf-8", errors="ignore")
        tables: list[tuple[str, int]] = []
        rls_tables: set[str] = set()
        policies: dict[str, list[tuple[int, str]]] = {}
        for i, raw in enumerate(text.splitlines(), 1):
            norm = normalize_line(raw)
            create = re.search(r"create\s+table\s+(?:if\s+not\s+exists\s+)?([a-zA-Z_][a-zA-Z0-9_]*)", norm, re.IGNORECASE)
            if create:
                tables.append((create.group(1).lower(), i))
            if re.search(r"enable\s+row\s+level\s+security", norm, re.IGNORECASE):
                table = re.search(r"alter\s+table\s+([a-zA-Z_][a-zA-Z0-9_]*)", norm, re.IGNORECASE)
                if table:
                    rls_tables.add(table.group(1).lower())
            policy = re.search(r"create\s+policy\s+\S+\s+on\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+.*(for\s+all|for\s+select|for\s+insert|for\s+update|for\s+delete)", norm, re.IGNORECASE)
            if policy:
                table = policy.group(1).lower()
                policies.setdefault(table, []).append((i, norm))
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
        for table, line in tables:
            if table not in rls_tables and not policies.get(table):
                self.add(
                    rule="table-without-rls",
                    severity=Severity.CRITICAL,
                    file=path,
                    line=line,
                    message=f"Table '{table}' has no Row Level Security policy.",
                    suggestion="Enable RLS and create explicit policies that check the requesting user.",
                    confidence="medium",
                )
        for table, entries in policies.items():
            for line, norm in entries:
                if "using" not in norm.lower() and "with check" not in norm.lower():
                    self.add(
                        rule="rls-policy-missing-condition",
                        severity=Severity.HIGH,
                        file=path,
                        line=line,
                        message=f"RLS policy on '{table}' lacks a USING or WITH CHECK condition.",
                        suggestion="Add a condition such as auth.uid() = user_id to restrict rows.",
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
