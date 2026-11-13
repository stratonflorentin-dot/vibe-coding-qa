"""Data-access layer for the dashboard.

Everything the API needs is expressed as explicit methods here so routes stay
thin and the SQL stays in one place. Rows are returned as plain dicts.
"""

import json
from typing import Any, Iterable

from .database import Database, utcnow


def _loads(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def finding_fingerprint(rule: str, file: str, line: int) -> str:
    """Stable identity for a finding: rule + file + line."""
    return f"{rule}|{file}|{line}"


class Store:
    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------------ repos
    def create_repository(
        self,
        *,
        name: str,
        source: str,
        source_type: str,
        main_language: str | None = None,
        frameworks: list[str] | None = None,
        package_manager: str | None = None,
        database_tech: list[str] | None = None,
        auth_tech: list[str] | None = None,
        deployment: list[str] | None = None,
        default_branch: str | None = None,
        last_commit_sha: str | None = None,
    ) -> dict:
        now = utcnow()
        cursor = self.db.execute(
            """
            INSERT INTO repositories
                (name, source, source_type, created_at, updated_at, main_language,
                 frameworks, package_manager, database_tech, auth_tech, deployment,
                 default_branch, last_commit_sha)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name, source, source_type, now, now, main_language,
                _dumps(frameworks or []), package_manager,
                _dumps(database_tech or []), _dumps(auth_tech or []),
                _dumps(deployment or []), default_branch, last_commit_sha,
            ),
        )
        return self.get_repository(cursor.lastrowid)

    def list_repositories(self) -> list[dict]:
        rows = self.db.query("SELECT * FROM repositories ORDER BY name COLLATE NOCASE")
        return [self._repo_row(row) for row in rows]

    def get_repository(self, repository_id: int) -> dict | None:
        row = self.db.query_one("SELECT * FROM repositories WHERE id = ?", (repository_id,))
        return self._repo_row(row) if row else None

    def get_repository_by_source(self, source: str) -> dict | None:
        row = self.db.query_one("SELECT * FROM repositories WHERE source = ?", (source,))
        return self._repo_row(row) if row else None

    def update_repository(self, repository_id: int, **fields) -> dict | None:
        if not fields:
            return self.get_repository(repository_id)
        json_fields = {"frameworks", "database_tech", "auth_tech", "deployment"}
        columns = []
        params: list[Any] = []
        for key, value in fields.items():
            columns.append(f"{key} = ?")
            params.append(_dumps(value) if key in json_fields else value)
        columns.append("updated_at = ?")
        params.append(utcnow())
        params.append(repository_id)
        self.db.execute(f"UPDATE repositories SET {', '.join(columns)} WHERE id = ?", tuple(params))
        return self.get_repository(repository_id)

    def delete_repository(self, repository_id: int) -> bool:
        cursor = self.db.execute("DELETE FROM repositories WHERE id = ?", (repository_id,))
        return cursor.rowcount > 0

    def _repo_row(self, row) -> dict:
        data = dict(row)
        for key in ("frameworks", "database_tech", "auth_tech", "deployment"):
            data[key] = _loads(data.get(key), [])
        latest = self.db.query_one(
            """
            SELECT id, status, overall_score, gate, critical_count, high_count,
                   completed_at, created_at, test_status
            FROM scans WHERE repository_id = ? AND status = 'completed'
            ORDER BY id DESC LIMIT 1
            """,
            (data["id"],),
        )
        data["latest_scan"] = dict(latest) if latest else None
        return data

    # ------------------------------------------------------------------ scans
    def create_scan(self, *, repository_id: int, profile: str, options: dict, trigger: str = "dashboard") -> dict:
        now = utcnow()
        cursor = self.db.execute(
            """
            INSERT INTO scans (repository_id, status, profile, created_at, options, trigger)
            VALUES (?, 'queued', ?, ?, ?, ?)
            """,
            (repository_id, profile, now, _dumps(options), trigger),
        )
        return self.get_scan(cursor.lastrowid)

    def update_scan(self, scan_id: int, **fields) -> dict | None:
        if not fields:
            return self.get_scan(scan_id)
        json_fields = {"scanner_versions", "coverage_gaps", "options"}
        columns = []
        params: list[Any] = []
        for key, value in fields.items():
            columns.append(f"{key} = ?")
            params.append(_dumps(value) if key in json_fields else value)
        params.append(scan_id)
        self.db.execute(f"UPDATE scans SET {', '.join(columns)} WHERE id = ?", tuple(params))
        return self.get_scan(scan_id)

    def get_scan(self, scan_id: int) -> dict | None:
        row = self.db.query_one("SELECT * FROM scans WHERE id = ?", (scan_id,))
        return self._scan_row(row) if row else None

    def list_scans(
        self,
        *,
        repository_id: int | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        clauses = []
        params: list[Any] = []
        if repository_id is not None:
            clauses.append("s.repository_id = ?")
            params.append(repository_id)
        if status:
            clauses.append("s.status = ?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        total_row = self.db.query_one(f"SELECT COUNT(*) AS c FROM scans s {where}", tuple(params))
        rows = self.db.query(
            f"""
            SELECT s.*, r.name AS repository_name, r.source AS repository_source
            FROM scans s JOIN repositories r ON r.id = s.repository_id
            {where}
            ORDER BY s.id DESC LIMIT ? OFFSET ?
            """,
            tuple(params) + (limit, offset),
        )
        return [self._scan_row(row, with_repo=True) for row in rows], int(total_row["c"])

    def latest_completed_scan(self, repository_id: int) -> dict | None:
        row = self.db.query_one(
            "SELECT * FROM scans WHERE repository_id = ? AND status = 'completed' ORDER BY id DESC LIMIT 1",
            (repository_id,),
        )
        return self._scan_row(row) if row else None

    def delete_scan(self, scan_id: int) -> bool:
        cursor = self.db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cursor.rowcount > 0

    def mark_interrupted_scans(self) -> list[int]:
        """Mark scans left queued/running by a previous process as failed."""
        rows = self.db.query("SELECT id FROM scans WHERE status IN ('queued', 'running')")
        ids = [row["id"] for row in rows]
        if ids:
            self.db.execute(
                """
                UPDATE scans
                SET status = 'failed', completed_at = ?,
                    error = COALESCE(error, 'Interrupted by a server restart before completion.')
                WHERE status IN ('queued', 'running')
                """,
                (utcnow(),),
            )
        return ids

    def _scan_row(self, row, with_repo: bool = False) -> dict:
        data = dict(row)
        data["options"] = _loads(data.get("options"), {})
        data["coverage_gaps"] = _loads(data.get("coverage_gaps"), [])
        data["scanner_versions"] = _loads(data.get("scanner_versions"), {})
        if not with_repo:
            repo = self.db.query_one("SELECT name, source FROM repositories WHERE id = ?", (data["repository_id"],))
            if repo:
                data["repository_name"] = repo["name"]
                data["repository_source"] = repo["source"]
        return data

    # --------------------------------------------------------------- findings
    def insert_findings(self, scan_id: int, repository_id: int, findings: Iterable[dict]) -> int:
        now = utcnow()
        rows = []
        count = 0
        for finding in findings:
            fingerprint = finding_fingerprint(finding["rule"], finding["file"], int(finding["line"]))
            prior = self.db.query_one(
                "SELECT first_seen_scan_id FROM findings WHERE fingerprint = ? AND repository_id = ? ORDER BY id LIMIT 1",
                (fingerprint, repository_id),
            )
            first_seen = prior["first_seen_scan_id"] if prior else scan_id
            rows.append((
                scan_id, repository_id, fingerprint, finding["rule"], finding["module"],
                finding["severity"], finding["file"], int(finding["line"]), int(finding.get("column", 0)),
                finding.get("message", ""), finding.get("suggestion", ""), finding.get("confidence", "medium"),
                1 if finding.get("fixable") else 0, "open", first_seen, now,
            ))
            count += 1
        if rows:
            self.db.executemany(
                """
                INSERT INTO findings
                    (scan_id, repository_id, fingerprint, rule, module, severity, file, line, column,
                     message, suggestion, confidence, fixable, status, first_seen_scan_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        return count

    def list_findings(
        self,
        *,
        repository_id: int | None = None,
        scan_id: int | None = None,
        severity: list[str] | None = None,
        module: list[str] | None = None,
        status: list[str] | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        clauses: list[str] = []
        params: list[Any] = []
        if scan_id is not None:
            clauses.append("f.scan_id = ?")
            params.append(scan_id)
        elif repository_id is not None:
            # Restrict to the newest scan per repository unless a scan is given,
            # so the UI shows the current state rather than historical duplicates.
            clauses.append(
                "f.scan_id = (SELECT id FROM scans WHERE repository_id = ? AND status = 'completed' ORDER BY id DESC LIMIT 1)"
            )
            params.append(repository_id)
        else:
            clauses.append(
                "f.scan_id IN (SELECT MAX(id) FROM scans WHERE status = 'completed' GROUP BY repository_id)"
            )
        if severity:
            clauses.append(f"f.severity IN ({','.join('?' for _ in severity)})")
            params.extend(severity)
        if module:
            clauses.append(f"f.module IN ({','.join('?' for _ in module)})")
            params.extend(module)
        if status:
            clauses.append(f"f.status IN ({','.join('?' for _ in status)})")
            params.extend(status)
        if search:
            like = f"%{search.lower()}%"
            clauses.append("(LOWER(f.rule) LIKE ? OR LOWER(f.file) LIKE ? OR LOWER(f.message) LIKE ?)")
            params.extend([like, like, like])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        total_row = self.db.query_one(f"SELECT COUNT(*) AS c FROM findings f {where}", tuple(params))
        rows = self.db.query(
            f"""
            SELECT f.*, r.name AS repository_name
            FROM findings f JOIN repositories r ON r.id = f.repository_id
            {where}
            ORDER BY
                CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                     WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                f.file, f.line
            LIMIT ? OFFSET ?
            """,
            tuple(params) + (limit, offset),
        )
        return [dict(row) for row in rows], int(total_row["c"])

    def get_finding(self, finding_id: int) -> dict | None:
        row = self.db.query_one(
            """
            SELECT f.*, r.name AS repository_name, r.source AS repository_source,
                   s.profile AS scan_profile, s.completed_at AS scan_completed_at
            FROM findings f
            JOIN repositories r ON r.id = f.repository_id
            LEFT JOIN scans s ON s.id = f.scan_id
            WHERE f.id = ?
            """,
            (finding_id,),
        )
        return dict(row) if row else None

    def set_finding_status(self, finding_id: int, status: str) -> dict | None:
        self.db.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
        return self.get_finding(finding_id)

    def finding_history(self, fingerprint: str, repository_id: int) -> list[dict]:
        rows = self.db.query(
            """
            SELECT f.id, f.scan_id, f.status, f.line, f.severity, f.created_at, s.completed_at
            FROM findings f LEFT JOIN scans s ON s.id = f.scan_id
            WHERE f.fingerprint = ? AND f.repository_id = ?
            ORDER BY f.id
            """,
            (fingerprint, repository_id),
        )
        return [dict(row) for row in rows]

    def severity_counts(self, repository_id: int | None = None, scan_id: int | None = None) -> dict[str, int]:
        clause = ""
        params: tuple = ()
        if scan_id is not None:
            clause = "WHERE scan_id = ?"
            params = (scan_id,)
        elif repository_id is not None:
            clause = (
                "WHERE scan_id = (SELECT id FROM scans WHERE repository_id = ? "
                "AND status = 'completed' ORDER BY id DESC LIMIT 1)"
            )
            params = (repository_id,)
        rows = self.db.query(f"SELECT severity, COUNT(*) AS c FROM findings {clause} GROUP BY severity", params)
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for row in rows:
            counts[row["severity"]] = int(row["c"])
        return counts

    def module_counts(self, repository_id: int | None = None, scan_id: int | None = None) -> dict[str, int]:
        clause = ""
        params: tuple = ()
        if scan_id is not None:
            clause = "WHERE scan_id = ?"
            params = (scan_id,)
        elif repository_id is not None:
            clause = (
                "WHERE scan_id = (SELECT id FROM scans WHERE repository_id = ? "
                "AND status = 'completed' ORDER BY id DESC LIMIT 1)"
            )
            params = (repository_id,)
        rows = self.db.query(f"SELECT module, COUNT(*) AS c FROM findings {clause} GROUP BY module", params)
        return {row["module"]: int(row["c"]) for row in rows}

    def findings_in_file(self, repository_id: int, file: str, exclude_id: int | None = None) -> list[dict]:
        """Other findings in the same file (used for related-finding context)."""
        rows = self.db.query(
            """
            SELECT f.id, f.rule, f.severity, f.line, f.message, f.module
            FROM findings f
            WHERE f.repository_id = ? AND f.file = ?
              AND f.scan_id = (SELECT id FROM scans WHERE repository_id = ? AND status = 'completed' ORDER BY id DESC LIMIT 1)
              AND (? IS NULL OR f.id != ?)
            ORDER BY f.line
            """,
            (repository_id, file, repository_id, exclude_id, exclude_id),
        )
        return [dict(row) for row in rows]

    def open_finding_count(self, repository_id: int | None = None) -> int:
        clause = ""
        params: tuple = ()
        if repository_id is not None:
            clause = (
                "AND scan_id = (SELECT id FROM scans WHERE repository_id = ? "
                "AND status = 'completed' ORDER BY id DESC LIMIT 1)"
            )
            params = (repository_id,)
        row = self.db.query_one(
            f"SELECT COUNT(*) AS c FROM findings WHERE status IN ('open', 'reviewed') {clause}",
            params,
        )
        return int(row["c"]) if row else 0

    def latest_completed_scans(self) -> list[dict]:
        """The most recent completed scan for every repository that has one."""
        rows = self.db.query(
            """
            SELECT s.*, r.name AS repository_name, r.source AS repository_source
            FROM scans s
            JOIN repositories r ON r.id = s.repository_id
            WHERE s.status = 'completed'
              AND s.id = (SELECT MAX(id) FROM scans WHERE repository_id = s.repository_id AND status = 'completed')
            ORDER BY s.completed_at DESC
            """
        )
        return [self._scan_row(row, with_repo=True) for row in rows]

    def recent_scans(self, limit: int = 30) -> list[dict]:
        rows = self.db.query(
            """
            SELECT s.*, r.name AS repository_name, r.source AS repository_source
            FROM scans s JOIN repositories r ON r.id = s.repository_id
            WHERE s.status = 'completed'
            ORDER BY s.id DESC LIMIT ?
            """,
            (limit,),
        )
        return [self._scan_row(row, with_repo=True) for row in rows]

    def count_repositories(self) -> int:
        row = self.db.query_one("SELECT COUNT(*) AS c FROM repositories")
        return int(row["c"]) if row else 0

    def count_scans(self) -> int:
        row = self.db.query_one("SELECT COUNT(*) AS c FROM scans")
        return int(row["c"]) if row else 0

    def severity_counts_for_scan(self, scan_id: int) -> dict[str, int]:
        return self.severity_counts(scan_id=scan_id)

    # ----------------------------------------------------------- scan events
    def add_event(self, scan_id: int, stage: str, *, status: str = "running", message: str = "", data: dict | None = None) -> dict:
        cursor = self.db.execute(
            "INSERT INTO scan_events (scan_id, ts, stage, status, message, data) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, utcnow(), stage, status, message, _dumps(data or {})),
        )
        return {"id": cursor.lastrowid, "scan_id": scan_id, "stage": stage, "status": status, "message": message, "data": data or {}}

    def list_events(self, scan_id: int, after_id: int = 0) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM scan_events WHERE scan_id = ? AND id > ? ORDER BY id",
            (scan_id, after_id),
        )
        result = []
        for row in rows:
            item = dict(row)
            item["data"] = _loads(item.get("data"), {})
            result.append(item)
        return result

    # -------------------------------------------------------------------- AI
    def add_ai_review(self, *, finding_id: int | None, scan_id: int | None, provider: str, model: str, kind: str, content: dict | None, error: str | None) -> dict:
        cursor = self.db.execute(
            """
            INSERT INTO ai_reviews (finding_id, scan_id, provider, model, kind, created_at, content, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (finding_id, scan_id, provider, model, kind, utcnow(), _dumps(content) if content is not None else None, error),
        )
        return {"id": cursor.lastrowid}

    def latest_ai_review(self, finding_id: int, kind: str | None = None) -> dict | None:
        clause = "WHERE finding_id = ?"
        params: list[Any] = [finding_id]
        if kind:
            clause += " AND kind = ?"
            params.append(kind)
        row = self.db.query_one(f"SELECT * FROM ai_reviews {clause} ORDER BY id DESC LIMIT 1", tuple(params))
        if not row:
            return None
        data = dict(row)
        data["content"] = _loads(data.get("content"), {})
        return data

    def create_conversation(self, repository_id: int | None, title: str) -> dict:
        now = utcnow()
        cursor = self.db.execute(
            "INSERT INTO ai_conversations (repository_id, title, created_at, updated_at) VALUES (?, ?, ?, ?)",
            (repository_id, title, now, now),
        )
        return {"id": cursor.lastrowid, "repository_id": repository_id, "title": title, "created_at": now, "updated_at": now}

    def list_conversations(self, repository_id: int | None = None) -> list[dict]:
        if repository_id is not None:
            rows = self.db.query(
                "SELECT * FROM ai_conversations WHERE repository_id = ? ORDER BY id DESC",
                (repository_id,),
            )
        else:
            rows = self.db.query("SELECT * FROM ai_conversations ORDER BY id DESC")
        return [dict(row) for row in rows]

    def get_conversation(self, conversation_id: int) -> dict | None:
        row = self.db.query_one("SELECT * FROM ai_conversations WHERE id = ?", (conversation_id,))
        if not row:
            return None
        data = dict(row)
        data["messages"] = self.list_messages(conversation_id)
        return data

    def delete_conversation(self, conversation_id: int) -> bool:
        cursor = self.db.execute("DELETE FROM ai_conversations WHERE id = ?", (conversation_id,))
        return cursor.rowcount > 0

    def add_message(self, conversation_id: int, role: str, content: str, metadata: dict | None = None) -> dict:
        now = utcnow()
        cursor = self.db.execute(
            "INSERT INTO ai_messages (conversation_id, role, content, created_at, metadata) VALUES (?, ?, ?, ?, ?)",
            (conversation_id, role, content, now, _dumps(metadata or {})),
        )
        self.db.execute("UPDATE ai_conversations SET updated_at = ? WHERE id = ?", (now, conversation_id))
        return {"id": cursor.lastrowid, "conversation_id": conversation_id, "role": role, "content": content, "created_at": now, "metadata": metadata or {}}

    def list_messages(self, conversation_id: int) -> list[dict]:
        rows = self.db.query("SELECT * FROM ai_messages WHERE conversation_id = ? ORDER BY id", (conversation_id,))
        result = []
        for row in rows:
            item = dict(row)
            item["metadata"] = _loads(item.get("metadata"), {})
            result.append(item)
        return result

    # ------------------------------------------------------- remediation
    def create_proposal(self, *, finding_id: int | None, repository_id: int, provider: str, model: str, file: str, original: str, proposed: str, diff: str, rationale: str) -> dict:
        now = utcnow()
        cursor = self.db.execute(
            """
            INSERT INTO remediation_proposals
                (finding_id, repository_id, status, created_at, updated_at, provider, model, file, original, proposed, diff, rationale)
            VALUES (?, ?, 'proposed', ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (finding_id, repository_id, now, now, provider, model, file, original, proposed, diff, rationale),
        )
        self.add_remediation_history(cursor.lastrowid, "proposed", detail="AI generated a proposed patch")
        return self.get_proposal(cursor.lastrowid)

    def get_proposal(self, proposal_id: int) -> dict | None:
        row = self.db.query_one("SELECT * FROM remediation_proposals WHERE id = ?", (proposal_id,))
        if not row:
            return None
        data = dict(row)
        data["history"] = self.list_remediation_history(proposal_id)
        return data

    def list_proposals(self, repository_id: int | None = None, finding_id: int | None = None) -> list[dict]:
        clauses = []
        params: list[Any] = []
        if repository_id is not None:
            clauses.append("repository_id = ?")
            params.append(repository_id)
        if finding_id is not None:
            clauses.append("finding_id = ?")
            params.append(finding_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self.db.query(f"SELECT * FROM remediation_proposals {where} ORDER BY id DESC", tuple(params))
        return [dict(row) for row in rows]

    def update_proposal(self, proposal_id: int, **fields) -> dict | None:
        if not fields:
            return self.get_proposal(proposal_id)
        columns = [f"{key} = ?" for key in fields]
        params: list[Any] = list(fields.values())
        columns.append("updated_at = ?")
        params.append(utcnow())
        params.append(proposal_id)
        self.db.execute(f"UPDATE remediation_proposals SET {', '.join(columns)} WHERE id = ?", tuple(params))
        return self.get_proposal(proposal_id)

    def add_remediation_history(self, proposal_id: int, action: str, *, actor: str = "local-user", detail: str = "") -> dict:
        cursor = self.db.execute(
            "INSERT INTO remediation_history (proposal_id, action, ts, actor, detail) VALUES (?, ?, ?, ?, ?)",
            (proposal_id, action, utcnow(), actor, detail),
        )
        return {"id": cursor.lastrowid, "proposal_id": proposal_id, "action": action, "detail": detail}

    def list_remediation_history(self, proposal_id: int) -> list[dict]:
        rows = self.db.query("SELECT * FROM remediation_history WHERE proposal_id = ? ORDER BY id", (proposal_id,))
        return [dict(row) for row in rows]

    # ------------------------------------------------------------- settings
    def get_setting(self, key: str, default: Any = None) -> Any:
        row = self.db.query_one("SELECT value FROM app_settings WHERE key = ?", (key,))
        return _loads(row["value"], default) if row else default

    def set_setting(self, key: str, value: Any) -> None:
        self.db.execute(
            """
            INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, _dumps(value), utcnow()),
        )

    def all_settings(self) -> dict:
        rows = self.db.query("SELECT key, value FROM app_settings")
        return {row["key"]: _loads(row["value"], None) for row in rows}

    def delete_setting(self, key: str) -> None:
        self.db.execute("DELETE FROM app_settings WHERE key = ?", (key,))

    # ------------------------------------------------------------------ users
    def count_users(self) -> int:
        row = self.db.query_one("SELECT COUNT(*) AS n FROM users")
        return int(row["n"]) if row else 0

    def count_active_owners(self, exclude_user_id: int | None = None) -> int:
        if exclude_user_id is None:
            row = self.db.query_one(
                "SELECT COUNT(*) AS n FROM users WHERE role = 'owner' AND is_active = 1"
            )
        else:
            row = self.db.query_one(
                "SELECT COUNT(*) AS n FROM users WHERE role = 'owner' AND is_active = 1 AND id != ?",
                (exclude_user_id,),
            )
        return int(row["n"]) if row else 0

    def create_user(self, *, username: str, password_hash: str, role: str, is_active: bool = True) -> dict:
        now = utcnow()
        cursor = self.db.execute(
            """
            INSERT INTO users (username, password_hash, role, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (username, password_hash, role, 1 if is_active else 0, now, now),
        )
        return self.get_user(cursor.lastrowid)

    def get_user(self, user_id: int) -> dict | None:
        row = self.db.query_one("SELECT * FROM users WHERE id = ?", (user_id,))
        return dict(row) if row else None

    def get_user_by_username(self, username: str) -> dict | None:
        row = self.db.query_one("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,))
        return dict(row) if row else None

    def list_users(self) -> list[dict]:
        rows = self.db.query(
            """
            SELECT id, username, role, is_active, created_at, updated_at, last_login_at
            FROM users ORDER BY id
            """
        )
        return [dict(row) for row in rows]

    def update_user(self, user_id: int, **fields) -> dict | None:
        allowed = {"username", "password_hash", "role", "is_active", "last_login_at"}
        columns: list[str] = []
        params: list[Any] = []
        for key, value in fields.items():
            if key not in allowed:
                continue
            columns.append(f"{key} = ?")
            params.append(int(bool(value)) if key == "is_active" else value)
        if not columns:
            return self.get_user(user_id)
        columns.append("updated_at = ?")
        params.append(utcnow())
        params.append(user_id)
        self.db.execute(f"UPDATE users SET {', '.join(columns)} WHERE id = ?", tuple(params))
        return self.get_user(user_id)

    def delete_user(self, user_id: int) -> bool:
        cursor = self.db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        return cursor.rowcount > 0

    # --------------------------------------------------------------- sessions
    def create_session(self, *, user_id: int, token_hash: str, expires_at: str, ip: str | None = None, user_agent: str | None = None) -> dict:
        cursor = self.db.execute(
            """
            INSERT INTO user_sessions (user_id, token_hash, created_at, expires_at, ip, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, token_hash, utcnow(), expires_at, ip, user_agent),
        )
        row = self.db.query_one("SELECT * FROM user_sessions WHERE id = ?", (cursor.lastrowid,))
        return dict(row)

    def get_session_with_user(self, token_hash: str) -> dict | None:
        row = self.db.query_one(
            """
            SELECT s.id AS session_id, s.user_id, s.expires_at, s.revoked_at,
                   u.username, u.role, u.is_active
            FROM user_sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ?
            """,
            (token_hash,),
        )
        return dict(row) if row else None

    def revoke_session(self, token_hash: str) -> bool:
        cursor = self.db.execute(
            "UPDATE user_sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
            (utcnow(), token_hash),
        )
        return cursor.rowcount > 0

    def revoke_user_sessions(self, user_id: int) -> int:
        cursor = self.db.execute(
            "UPDATE user_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (utcnow(), user_id),
        )
        return cursor.rowcount

    def purge_expired_sessions(self) -> int:
        cursor = self.db.execute("DELETE FROM user_sessions WHERE expires_at < ?", (utcnow(),))
        return cursor.rowcount

    # ------------------------------------------------------------------ audit
    def add_audit(self, *, action: str, user_id: int | None = None, username: str | None = None, target: str | None = None, detail: str | None = None, ip: str | None = None) -> None:
        self.db.execute(
            """
            INSERT INTO audit_log (ts, user_id, username, action, target, detail, ip)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (utcnow(), user_id, username, action, target, detail, ip),
        )

    def list_audit(self, limit: int = 100) -> list[dict]:
        rows = self.db.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (int(limit),))
        return [dict(row) for row in rows]

    # ----------------------------------------------------------- intelligence
    def create_intelligence_task(self, *, user_id: int | None, project_id: int | None, operation: str) -> dict:
        cursor = self.db.execute(
            "INSERT INTO intelligence_tasks (user_id, project_id, operation, status, created_at) VALUES (?, ?, ?, 'running', ?)",
            (user_id, project_id, operation, utcnow()),
        )
        return dict(self.db.query_one("SELECT * FROM intelligence_tasks WHERE id = ?", (cursor.lastrowid,)))

    def complete_intelligence_task(self, task_id: int, *, status: str, error_code: str | None = None) -> None:
        self.db.execute(
            "UPDATE intelligence_tasks SET status = ?, error_code = ?, completed_at = ? WHERE id = ?",
            (status, error_code, utcnow(), task_id),
        )

    def record_model_execution(
        self, *, task_id: int, provider_id: str | None, model_id: str | None,
        execution_status: str, latency_ms: int | None = None, token_usage: int | None = None,
        estimated_cost: float | None = None, fallback_used: bool = False,
    ) -> None:
        self.db.execute(
            """
            INSERT INTO model_executions
                (task_id, provider_id, model_id, execution_status, latency_ms, token_usage,
                 estimated_cost, fallback_used, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (task_id, provider_id, model_id, execution_status, latency_ms, token_usage,
             estimated_cost, 1 if fallback_used else 0, utcnow()),
        )

    def get_intelligence_task(self, task_id: int) -> dict | None:
        row = self.db.query_one("SELECT * FROM intelligence_tasks WHERE id = ?", (task_id,))
        if not row:
            return None
        task = dict(row)
        task["executions"] = [
            dict(r) for r in self.db.query(
                "SELECT * FROM model_executions WHERE task_id = ? ORDER BY id", (task_id,)
            )
        ]
        return task

    def list_intelligence_tasks(self, *, project_id: int | None = None, limit: int = 50) -> list[dict]:
        if project_id is None:
            rows = self.db.query("SELECT * FROM intelligence_tasks ORDER BY id DESC LIMIT ?", (int(limit),))
        else:
            rows = self.db.query(
                "SELECT * FROM intelligence_tasks WHERE project_id = ? ORDER BY id DESC LIMIT ?",
                (project_id, int(limit)),
            )
        return [dict(row) for row in rows]

    # ------------------------------------------------------- security workers
    def create_security_worker(
        self,
        *,
        name: str,
        base_url: str,
        token: str | None,
        placement: str = "remote",
        allowed_networks: str | None = None,
    ) -> dict:
        now = utcnow()
        cursor = self.db.execute(
            """
            INSERT INTO security_workers
                (name, base_url, token, placement, allowed_networks, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (name, base_url, token, placement, allowed_networks, now, now),
        )
        return self.get_security_worker(cursor.lastrowid)

    def get_security_worker(self, worker_id: int) -> dict | None:
        row = self.db.query_one("SELECT * FROM security_workers WHERE id = ?", (worker_id,))
        return self._security_worker_row(row)

    def get_security_worker_by_name(self, name: str) -> dict | None:
        row = self.db.query_one("SELECT * FROM security_workers WHERE name = ?", (name,))
        return self._security_worker_row(row)

    def list_security_workers(self) -> list[dict]:
        rows = self.db.query("SELECT * FROM security_workers ORDER BY id")
        return [self._security_worker_row(row) for row in rows]

    def update_security_worker(self, worker_id: int, **fields) -> dict | None:
        allowed = {
            "name", "base_url", "token", "placement", "allowed_networks", "enabled",
            "last_seen_at", "last_status", "last_detail", "worker_version", "tools",
        }
        columns: list[str] = []
        params: list[Any] = []
        for key, value in fields.items():
            if key not in allowed:
                continue
            columns.append(f"{key} = ?")
            if key in ("enabled",):
                params.append(1 if value else 0)
            elif key == "tools":
                params.append(_dumps(value))
            else:
                params.append(value)
        if not columns:
            return self.get_security_worker(worker_id)
        columns.append("updated_at = ?")
        params.append(utcnow())
        params.append(worker_id)
        self.db.execute(f"UPDATE security_workers SET {', '.join(columns)} WHERE id = ?", tuple(params))
        return self.get_security_worker(worker_id)

    def delete_security_worker(self, worker_id: int) -> bool:
        cursor = self.db.execute("DELETE FROM security_workers WHERE id = ?", (worker_id,))
        return cursor.rowcount > 0

    @staticmethod
    def _security_worker_row(row) -> dict | None:
        if row is None:
            return None
        data = dict(row)
        data["tools"] = _loads(data.get("tools"), [])
        data["enabled"] = bool(data.get("enabled"))
        return data

    # ------------------------------------------------------- security targets
    def create_security_target(
        self,
        *,
        value: str,
        kind: str = "url",
        environment: str = "staging",
        ownership_confirmed: bool = False,
        scope: str | None = None,
        profile: str = "basic",
        rate_limit: int | None = None,
        verify_method: str | None = None,
        verify_token: str | None = None,
        allowed_cidrs: str | None = None,
        worker_id: int | None = None,
        created_by: int | None = None,
        notes: str | None = None,
    ) -> dict:
        cursor = self.db.execute(
            """
            INSERT INTO security_targets
                (value, kind, environment, ownership_confirmed, scope, profile, rate_limit,
                 verify_method, verify_token, verify_status, allowed_cidrs, worker_id, created_by,
                 notes, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'unverified', ?, ?, ?, ?, ?)
            """,
            (
                value, kind, environment, 1 if ownership_confirmed else 0, scope, profile, rate_limit,
                verify_method, verify_token, allowed_cidrs, worker_id, created_by, notes, utcnow(),
            ),
        )
        return self.get_security_target(cursor.lastrowid)

    def get_security_target(self, target_id: int) -> dict | None:
        row = self.db.query_one("SELECT * FROM security_targets WHERE id = ?", (target_id,))
        return self._security_target_row(row)

    def get_security_target_by_value(self, value: str) -> dict | None:
        row = self.db.query_one("SELECT * FROM security_targets WHERE value = ?", (value,))
        return self._security_target_row(row)

    def list_security_targets(self) -> list[dict]:
        rows = self.db.query("SELECT * FROM security_targets ORDER BY id DESC")
        return [self._security_target_row(row) for row in rows]

    def update_security_target(self, target_id: int, **fields) -> dict | None:
        allowed = {
            "value", "kind", "environment", "ownership_confirmed", "scope", "profile", "rate_limit",
            "verify_method", "verify_token", "verify_status", "verify_detail", "allowed_cidrs",
            "worker_id", "notes", "verified_at",
        }
        columns: list[str] = []
        params: list[Any] = []
        for key, value in fields.items():
            if key not in allowed:
                continue
            columns.append(f"{key} = ?")
            params.append(1 if (key == "ownership_confirmed" and value) else (0 if key == "ownership_confirmed" else value))
        if not columns:
            return self.get_security_target(target_id)
        params.append(target_id)
        self.db.execute(f"UPDATE security_targets SET {', '.join(columns)} WHERE id = ?", tuple(params))
        return self.get_security_target(target_id)

    def delete_security_target(self, target_id: int) -> bool:
        cursor = self.db.execute("DELETE FROM security_targets WHERE id = ?", (target_id,))
        return cursor.rowcount > 0

    @staticmethod
    def _security_target_row(row) -> dict | None:
        if row is None:
            return None
        data = dict(row)
        data["ownership_confirmed"] = bool(data.get("ownership_confirmed"))
        return data

    # ---------------------------------------------------------- security jobs
    def create_security_job(
        self,
        *,
        target_id: int,
        worker_id: int | None,
        profile: str,
        tools: list[str],
        intrusive: bool = False,
        actor: str | None = None,
        status: str = "queued",
        message: str | None = None,
    ) -> dict:
        cursor = self.db.execute(
            """
            INSERT INTO security_jobs
                (target_id, worker_id, profile, tools, status, intrusive, created_at, message, actor)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target_id, worker_id, profile, _dumps(tools), status,
                1 if intrusive else 0, utcnow(), message, actor,
            ),
        )
        return self.get_security_job(cursor.lastrowid)

    def get_security_job(self, job_id: int) -> dict | None:
        row = self.db.query_one("SELECT * FROM security_jobs WHERE id = ?", (job_id,))
        return self._security_job_row(row)

    def list_security_jobs(self, *, status: str | None = None, target_id: int | None = None, limit: int = 100, offset: int = 0) -> tuple[list[dict], int]:
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if target_id is not None:
            clauses.append("target_id = ?")
            params.append(target_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        total_row = self.db.query_one(f"SELECT COUNT(*) AS n FROM security_jobs {where}", tuple(params))
        rows = self.db.query(
            f"SELECT * FROM security_jobs {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            tuple(params) + (int(limit), int(offset)),
        )
        return [self._security_job_row(row) for row in rows], int(total_row["n"]) if total_row else 0

    def update_security_job(self, job_id: int, **fields) -> dict | None:
        allowed = {
            "status", "started_at", "completed_at", "cancel_requested", "findings_count",
            "message", "error", "remote_job_id", "worker_id", "tools", "intrusive",
        }
        columns: list[str] = []
        params: list[Any] = []
        for key, value in fields.items():
            if key not in allowed:
                continue
            columns.append(f"{key} = ?")
            if key in ("cancel_requested", "intrusive"):
                params.append(1 if value else 0)
            elif key == "tools":
                params.append(_dumps(value))
            else:
                params.append(value)
        if not columns:
            return self.get_security_job(job_id)
        params.append(job_id)
        self.db.execute(f"UPDATE security_jobs SET {', '.join(columns)} WHERE id = ?", tuple(params))
        return self.get_security_job(job_id)

    def mark_interrupted_security_jobs(self) -> list[int]:
        """Mark queued/running security jobs failed after an unclean restart."""
        rows = self.db.query("SELECT id FROM security_jobs WHERE status IN ('queued', 'running')")
        ids = [int(row["id"]) for row in rows]
        for job_id in ids:
            self.db.execute(
                "UPDATE security_jobs SET status = 'failed', completed_at = ?, error = ? WHERE id = ?",
                (utcnow(), "Interrupted by a dashboard restart.", job_id),
            )
        return ids

    @staticmethod
    def _security_job_row(row) -> dict | None:
        if row is None:
            return None
        data = dict(row)
        data["tools"] = _loads(data.get("tools"), [])
        data["intrusive"] = bool(data.get("intrusive"))
        data["cancel_requested"] = bool(data.get("cancel_requested"))
        return data

    # ------------------------------------------------------ security findings
    def upsert_security_finding(
        self,
        *,
        job_id: int,
        target_id: int,
        fingerprint: str,
        dedupe_key: str,
        tool: str,
        tool_version: str | None,
        target: str,
        endpoint: str | None,
        title: str,
        category: str | None,
        description: str | None,
        severity: str,
        confidence: str | None,
        evidence: str | None,
        remediation: str | None,
        references: list[str] | None,
        detected_at: str,
    ) -> tuple[dict, bool]:
        """Insert a finding, or fold a duplicate into the existing row.

        Uniqueness is ``(target_id, dedupe_key)`` so the same vulnerability seen
        by several tools becomes one row whose ``tools`` list records each source;
        ``occurrences`` counts repeat sightings. Returns ``(row, created)``.
        """
        existing = self.db.query_one(
            "SELECT * FROM security_findings WHERE target_id = ? AND dedupe_key = ?",
            (target_id, dedupe_key),
        )
        if existing is not None:
            tools = _loads(existing["tools"], []) or []
            if tool not in tools:
                tools.append(tool)
            self.db.execute(
                """
                UPDATE security_findings
                SET occurrences = occurrences + 1, tools = ?, detected_at = ?,
                    tool_version = COALESCE(?, tool_version),
                    evidence = COALESCE(?, evidence)
                WHERE id = ?
                """,
                (_dumps(tools), detected_at, tool_version, evidence, existing["id"]),
            )
            self.db.execute(
                """
                INSERT OR IGNORE INTO security_finding_occurrences
                    (finding_id, job_id, tool, tool_version, evidence, detected_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (existing["id"], job_id, tool, tool_version, evidence, detected_at, utcnow()),
            )
            return self.get_security_finding(existing["id"]), False

        cursor = self.db.execute(
            """
            INSERT INTO security_findings
                (job_id, target_id, fingerprint, dedupe_key, tool, tools, tool_version, target,
                 endpoint, title, category, description, severity, confidence, evidence,
                 remediation, references_json, detected_at, first_seen_job_id, occurrences, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
            """,
            (
                job_id, target_id, fingerprint, dedupe_key, tool, _dumps([tool]), tool_version, target,
                endpoint, title, category, description, severity, confidence, evidence,
                remediation, _dumps(references or []), detected_at, job_id, utcnow(),
            ),
        )
        self.db.execute(
            """
            INSERT OR IGNORE INTO security_finding_occurrences
                (finding_id, job_id, tool, tool_version, evidence, detected_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (cursor.lastrowid, job_id, tool, tool_version, evidence, detected_at, utcnow()),
        )
        return self.get_security_finding(cursor.lastrowid), True

    def get_security_finding(self, finding_id: int) -> dict | None:
        row = self.db.query_one("SELECT * FROM security_findings WHERE id = ?", (finding_id,))
        return self._security_finding_row(row)

    def list_security_findings(
        self,
        *,
        target_id: int | None = None,
        job_id: int | None = None,
        severity: str | None = None,
        status: str | None = None,
        verification_job_id: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        clauses: list[str] = []
        params: list[Any] = []
        if target_id is not None:
            clauses.append("target_id = ?")
            params.append(target_id)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if verification_job_id is not None:
            clauses.append("verification_job_id = ?")
            params.append(verification_job_id)
        elif job_id is not None:
            clauses.append(
                "(job_id = ? OR EXISTS (SELECT 1 FROM security_finding_occurrences o "
                "WHERE o.finding_id = security_findings.id AND o.job_id = ?))"
            )
            params.extend((job_id, job_id))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        total_row = self.db.query_one(f"SELECT COUNT(*) AS n FROM security_findings {where}", tuple(params))
        rows = self.db.query(
            f"""
            SELECT * FROM security_findings {where}
            ORDER BY CASE severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                WHEN 'low' THEN 3 ELSE 4 END, id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params) + (int(limit), int(offset)),
        )
        return [self._security_finding_row(row) for row in rows], int(total_row["n"]) if total_row else 0

    def set_security_finding_status(self, finding_id: int, status: str) -> dict | None:
        self.db.execute("UPDATE security_findings SET status = ? WHERE id = ?", (status, finding_id))
        return self.get_security_finding(finding_id)

    def set_security_finding_verification(
        self,
        finding_id: int,
        verification_status: str,
        *,
        verification_job_id: int | None = None,
    ) -> dict | None:
        """Record deterministic verification evidence and its source job."""
        verified_at = utcnow() if verification_status == "verified" else None
        self.db.execute(
            """
            UPDATE security_findings
            SET verification_status = ?, verified_at = ?, verification_checked_at = ?,
                verification_job_id = COALESCE(?, verification_job_id)
            WHERE id = ?
            """,
            (verification_status, verified_at, utcnow(), verification_job_id, finding_id),
        )
        return self.get_security_finding(finding_id)

    def security_severity_counts(self, target_id: int | None = None) -> dict[str, int]:
        if target_id is None:
            rows = self.db.query("SELECT severity, COUNT(*) AS n FROM security_findings GROUP BY severity")
        else:
            rows = self.db.query(
                "SELECT severity, COUNT(*) AS n FROM security_findings WHERE target_id = ? GROUP BY severity",
                (target_id,),
            )
        counts = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
        for row in rows:
            counts[str(row["severity"]).lower()] = int(row["n"])
        return counts

    @staticmethod
    def _security_finding_row(row) -> dict | None:
        if row is None:
            return None
        data = dict(row)
        data["tools"] = _loads(data.get("tools"), [])
        data["references"] = _loads(data.pop("references_json", None), [])
        return data

    # ------------------------------------------------------ security evidence
    def add_security_evidence(
        self,
        *,
        job_id: int,
        finding_id: int | None,
        tool: str,
        content: str,
        kind: str = "raw",
    ) -> dict:
        import hashlib

        digest = hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()
        cursor = self.db.execute(
            """
            INSERT INTO security_evidence (job_id, finding_id, tool, kind, content, content_sha256, byte_size, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (job_id, finding_id, tool, kind, content, digest, len(content.encode("utf-8", "replace")), utcnow()),
        )
        row = self.db.query_one("SELECT * FROM security_evidence WHERE id = ?", (cursor.lastrowid,))
        return dict(row)

    def list_security_evidence(self, *, job_id: int | None = None, finding_id: int | None = None, limit: int = 100) -> list[dict]:
        clauses: list[str] = []
        params: list[Any] = []
        if job_id is not None:
            clauses.append("job_id = ?")
            params.append(job_id)
        if finding_id is not None:
            clauses.append("finding_id = ?")
            params.append(finding_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self.db.query(
            f"SELECT * FROM security_evidence {where} ORDER BY id DESC LIMIT ?",
            tuple(params) + (int(limit),),
        )
        return [dict(row) for row in rows]

    def get_security_evidence(self, evidence_id: int) -> dict | None:
        row = self.db.query_one("SELECT * FROM security_evidence WHERE id = ?", (evidence_id,))
        return dict(row) if row else None
