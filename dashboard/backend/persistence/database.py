"""SQLite persistence for the dashboard.

A tiny, dependency-free data layer: no ORM, just ``sqlite3`` with explicit
migrations. Scan history must survive restarts and interrupted scans must be
identifiable, so everything the engine produces is persisted here.
"""

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# Each entry is (version, [statements]). Migrations are append-only; never edit a
# shipped migration, add a new one.
MIGRATIONS: list[tuple[int, list[str]]] = [
    (
        1,
        [
            """
            CREATE TABLE repositories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                source TEXT NOT NULL UNIQUE,
                source_type TEXT NOT NULL DEFAULT 'local',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                main_language TEXT,
                frameworks TEXT,
                package_manager TEXT,
                database_tech TEXT,
                auth_tech TEXT,
                deployment TEXT,
                default_branch TEXT,
                last_commit_sha TEXT,
                last_scan_id INTEGER
            )
            """,
            """
            CREATE TABLE scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
                status TEXT NOT NULL,
                profile TEXT NOT NULL,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                commit_sha TEXT,
                overall_score REAL,
                gate TEXT,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0,
                test_status TEXT,
                tests_executed INTEGER,
                tests_passed INTEGER,
                tests_failed INTEGER,
                tests_skipped INTEGER,
                duration_ms INTEGER,
                scanner_versions TEXT,
                coverage_gaps TEXT,
                ai_review_status TEXT,
                error TEXT,
                options TEXT,
                trigger TEXT
            )
            """,
            "CREATE INDEX idx_scans_repo ON scans(repository_id, id DESC)",
            """
            CREATE TABLE findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
                fingerprint TEXT NOT NULL,
                rule TEXT NOT NULL,
                module TEXT NOT NULL,
                severity TEXT NOT NULL,
                file TEXT NOT NULL,
                line INTEGER NOT NULL,
                column INTEGER DEFAULT 0,
                message TEXT,
                suggestion TEXT,
                confidence TEXT,
                fixable INTEGER DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'open',
                first_seen_scan_id INTEGER,
                created_at TEXT NOT NULL
            )
            """,
            "CREATE INDEX idx_findings_scan ON findings(scan_id)",
            "CREATE INDEX idx_findings_repo ON findings(repository_id, status)",
            "CREATE INDEX idx_findings_fingerprint ON findings(fingerprint)",
            """
            CREATE TABLE scan_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                ts TEXT NOT NULL,
                stage TEXT NOT NULL,
                status TEXT,
                message TEXT,
                data TEXT
            )
            """,
            "CREATE INDEX idx_events_scan ON scan_events(scan_id, id)",
            """
            CREATE TABLE ai_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
                scan_id INTEGER,
                provider TEXT,
                model TEXT,
                kind TEXT,
                created_at TEXT NOT NULL,
                content TEXT,
                error TEXT
            )
            """,
            """
            CREATE TABLE ai_conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository_id INTEGER REFERENCES repositories(id) ON DELETE SET NULL,
                title TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE ai_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL REFERENCES ai_conversations(id) ON DELETE CASCADE,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                metadata TEXT
            )
            """,
            "CREATE INDEX idx_messages_conversation ON ai_messages(conversation_id, id)",
            """
            CREATE TABLE remediation_proposals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
                repository_id INTEGER REFERENCES repositories(id) ON DELETE CASCADE,
                status TEXT NOT NULL DEFAULT 'proposed',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                provider TEXT,
                model TEXT,
                file TEXT,
                original TEXT,
                proposed TEXT,
                diff TEXT,
                rationale TEXT,
                error TEXT
            )
            """,
            """
            CREATE TABLE remediation_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                proposal_id INTEGER NOT NULL REFERENCES remediation_proposals(id) ON DELETE CASCADE,
                action TEXT NOT NULL,
                ts TEXT NOT NULL,
                actor TEXT,
                detail TEXT
            )
            """,
            """
            CREATE TABLE app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
        ],
    ),
    (
        2,
        [
            # Multi-user accounts for a self-hosted installation. The install is
            # open or single-credential until the first user is created here.
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_login_at TEXT
            )
            """,
            # Server-side sessions so a login can expire and be revoked. Only the
            # SHA-256 of the token is stored, never the token itself.
            """
            CREATE TABLE user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                ip TEXT,
                user_agent TEXT
            )
            """,
            "CREATE INDEX idx_user_sessions_token ON user_sessions(token_hash)",
            "CREATE INDEX idx_user_sessions_user ON user_sessions(user_id)",
            # Append-only audit trail for sensitive actions.
            """
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                username TEXT,
                action TEXT NOT NULL,
                target TEXT,
                detail TEXT,
                ip TEXT
            )
            """,
            "CREATE INDEX idx_audit_id ON audit_log(id DESC)",
        ],
    ),
    (
        3,
        [
            # Optional Kali Security Worker fleet. A worker is an independently
            # deployed container the customer runs on their own VPS/LAN; the main
            # API never executes a tool itself and never mounts the Docker socket.
            # ``token`` authenticates the API to the worker (outbound only).
            """
            CREATE TABLE security_workers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                base_url TEXT NOT NULL,
                token TEXT,
                placement TEXT NOT NULL DEFAULT 'remote',
                allowed_networks TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_seen_at TEXT,
                last_status TEXT,
                last_detail TEXT,
                worker_version TEXT,
                tools TEXT
            )
            """,
            # An authorised target. Registration never contacts the target: the
            # allowlist entry and the ownership check are prerequisites for a scan.
            """
            CREATE TABLE security_targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                value TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'url',
                environment TEXT NOT NULL DEFAULT 'staging',
                ownership_confirmed INTEGER NOT NULL DEFAULT 0,
                scope TEXT,
                profile TEXT NOT NULL DEFAULT 'basic',
                rate_limit INTEGER,
                verify_method TEXT,
                verify_token TEXT,
                verify_status TEXT NOT NULL DEFAULT 'unverified',
                verify_detail TEXT,
                allowed_cidrs TEXT,
                worker_id INTEGER REFERENCES security_workers(id) ON DELETE SET NULL,
                created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                notes TEXT,
                created_at TEXT NOT NULL,
                verified_at TEXT
            )
            """,
            "CREATE UNIQUE INDEX idx_security_targets_value ON security_targets(value)",
            """
            CREATE TABLE security_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL REFERENCES security_targets(id) ON DELETE CASCADE,
                worker_id INTEGER REFERENCES security_workers(id) ON DELETE SET NULL,
                profile TEXT NOT NULL,
                tools TEXT,
                status TEXT NOT NULL,
                intrusive INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                cancel_requested INTEGER NOT NULL DEFAULT 0,
                findings_count INTEGER NOT NULL DEFAULT 0,
                message TEXT,
                error TEXT,
                remote_job_id TEXT,
                actor TEXT
            )
            """,
            "CREATE INDEX idx_security_jobs_target ON security_jobs(target_id, id DESC)",
            "CREATE INDEX idx_security_jobs_status ON security_jobs(status)",
            # Normalised findings. ``dedupe_key`` collapses the same vulnerability
            # reported by several tools against the same endpoint into one row;
            # ``tools`` lists every tool that saw it, and each tool's raw output is
            # kept as a separately access-controlled evidence artifact.
            """
            CREATE TABLE security_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER NOT NULL REFERENCES security_jobs(id) ON DELETE CASCADE,
                target_id INTEGER NOT NULL REFERENCES security_targets(id) ON DELETE CASCADE,
                fingerprint TEXT NOT NULL,
                dedupe_key TEXT NOT NULL,
                tool TEXT NOT NULL,
                tools TEXT,
                tool_version TEXT,
                target TEXT NOT NULL,
                endpoint TEXT,
                title TEXT NOT NULL,
                category TEXT,
                description TEXT,
                severity TEXT NOT NULL,
                confidence TEXT,
                evidence TEXT,
                remediation TEXT,
                references_json TEXT,
                detected_at TEXT NOT NULL,
                verification_status TEXT NOT NULL DEFAULT 'unverified',
                verified_at TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                first_seen_job_id INTEGER,
                occurrences INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
            """,
            "CREATE INDEX idx_security_findings_job ON security_findings(job_id)",
            "CREATE INDEX idx_security_findings_target ON security_findings(target_id, severity)",
            "CREATE UNIQUE INDEX idx_security_findings_dedupe ON security_findings(target_id, dedupe_key)",
            # Raw tool output, kept verbatim but only ever served to an authorised
            # user. Never interpreted as instructions.
            """
            CREATE TABLE security_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER NOT NULL REFERENCES security_jobs(id) ON DELETE CASCADE,
                finding_id INTEGER REFERENCES security_findings(id) ON DELETE SET NULL,
                tool TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'raw',
                content TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                byte_size INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """,
            "CREATE INDEX idx_security_evidence_job ON security_evidence(job_id)",
        ],
    ),
    (
        4,
        [
            "ALTER TABLE security_findings ADD COLUMN verification_job_id INTEGER REFERENCES security_jobs(id) ON DELETE SET NULL",
            "ALTER TABLE security_findings ADD COLUMN verification_checked_at TEXT",
            """
            CREATE TABLE security_finding_occurrences (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL REFERENCES security_findings(id) ON DELETE CASCADE,
                job_id INTEGER NOT NULL REFERENCES security_jobs(id) ON DELETE CASCADE,
                tool TEXT NOT NULL,
                tool_version TEXT,
                evidence TEXT,
                detected_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(finding_id, job_id, tool)
            )
            """,
            "CREATE INDEX idx_security_occurrences_job ON security_finding_occurrences(job_id, finding_id)",
        ],
    ),
]


class Database:
    """Thread-safe SQLite wrapper with WAL and per-thread connections."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._write_lock = threading.Lock()
        self._conn_lock = threading.Lock()
        # Every connection is tracked so shutdown can release the file handles
        # (worker threads open their own connection and Windows keeps the file
        # locked until all of them are closed).
        self._open_connections: list[sqlite3.Connection] = []
        self._memory_conn: sqlite3.Connection | None = None
        if str(self.path) == ":memory:":
            # A shared in-memory database must keep one connection alive, otherwise
            # each connect() would see an empty schema.
            self._memory_conn = self._connect_raw()
        self.migrate()

    def _connect_raw(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        with self._conn_lock:
            self._open_connections.append(conn)
        return conn

    def connection(self) -> sqlite3.Connection:
        if self._memory_conn is not None:
            return self._memory_conn
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._connect_raw()
            self._local.conn = conn
        return conn

    def close(self) -> None:
        """Close every connection opened by this database."""
        with self._conn_lock:
            connections = list(self._open_connections)
            self._open_connections.clear()
        for conn in connections:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        self._local = threading.local()
        self._memory_conn = None

    def applied_versions(self) -> set[int]:
        conn = self.connection()
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        rows = conn.execute("SELECT version FROM schema_migrations").fetchall()
        return {row["version"] for row in rows}

    def migrate(self) -> list[int]:
        applied = self.applied_versions()
        newly: list[int] = []
        conn = self.connection()
        with self._write_lock:
            for version, statements in MIGRATIONS:
                if version in applied:
                    continue
                for statement in statements:
                    conn.execute(statement)
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (version, utcnow()),
                )
                conn.commit()
                newly.append(version)
        return newly

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        conn = self.connection()
        with self._write_lock:
            cursor = conn.execute(sql, params)
            conn.commit()
            return cursor

    def executemany(self, sql: str, seq_params) -> None:
        conn = self.connection()
        with self._write_lock:
            conn.executemany(sql, seq_params)
            conn.commit()

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        return self.connection().execute(sql, params).fetchall()

    def query_one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        return self.connection().execute(sql, params).fetchone()
