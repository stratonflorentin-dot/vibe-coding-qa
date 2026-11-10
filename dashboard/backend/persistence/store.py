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
