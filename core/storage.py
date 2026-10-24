"""SQLite persistence and restoration for PhantomX assessment sessions."""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from core.models import (
    Endpoint, Finding, Observation, Service, Session, ToolResult,
)


def _endpoint(data):
    return Endpoint(**data) if data else None


def _finding(data):
    return Finding(**data)


def _observation(data):
    item = dict(data)
    item["endpoint"] = _endpoint(item.get("endpoint"))
    return Observation(**item)


def _tool_result(data):
    item = dict(data)
    item["services"] = [Service(**x) for x in item.get("services", [])]
    item["endpoints"] = [Endpoint(**x) for x in item.get("endpoints", [])]
    item["observations"] = [
        _observation(x) for x in item.get("observations", [])
    ]
    item["findings"] = [_finding(x) for x in item.get("findings", [])]
    return ToolResult(**item)


def session_from_dict(data):
    """Rebuild a Session and all nested dataclass models from JSON data."""
    return Session(
        target=data["target"],
        profile=data["profile"],
        started_at=data["started_at"],
        results=[_tool_result(x) for x in data.get("results", [])],
        notes=list(data.get("notes", [])),
        session_id=data["session_id"],
    )


class SQLiteSessionStore:
    """Store complete session payloads in SQLite with indexed metadata."""

    def __init__(self, path="data/phantomx.sqlite3"):
        self.path = Path(path)
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(str(self.path), timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self):
        with self._connect() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    saved_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
            """)
            db.execute("""
                CREATE INDEX IF NOT EXISTS idx_sessions_started_at
                ON sessions(started_at DESC)
            """)
            db.execute("""
                CREATE INDEX IF NOT EXISTS idx_sessions_target
                ON sessions(target)
            """)

    def save(self, session):
        """Save or update a session atomically."""
        payload = json.dumps(session.as_dict(), ensure_ascii=False)
        saved_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as db:
            db.execute("""
                INSERT INTO sessions
                    (session_id, target, profile, started_at, saved_at, payload)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    target=excluded.target,
                    profile=excluded.profile,
                    started_at=excluded.started_at,
                    saved_at=excluded.saved_at,
                    payload=excluded.payload
            """, (
                session.session_id, session.target, session.profile,
                session.started_at, saved_at, payload,
            ))
        return session.session_id

    def list_sessions(self, limit=20):
        limit = max(1, min(int(limit), 500))
        with self._connect() as db:
            rows = db.execute("""
                SELECT session_id, target, profile, started_at, saved_at
                FROM sessions
                ORDER BY started_at DESC, saved_at DESC
                LIMIT ?
            """, (limit,)).fetchall()
        return [dict(row) for row in rows]

    def load(self, session_id):
        with self._connect() as db:
            row = db.execute(
                "SELECT payload FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        if row is None:
            return None
        return session_from_dict(json.loads(row["payload"]))

    def count(self):
        with self._connect() as db:
            return db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
