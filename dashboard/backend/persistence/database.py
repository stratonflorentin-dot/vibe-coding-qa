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
