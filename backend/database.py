import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path


DB_PATH = Path(__file__).resolve().parent / "trinetra.db"


class Database:
    def __init__(self, path: Path = DB_PATH):
        self.path = path
        self.lock = threading.Lock()
        self._initialize()

    def connect(self):
        connection = sqlite3.connect(self.path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self):
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    category TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    score INTEGER NOT NULL DEFAULT 0,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    metadata TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS system_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    cpu REAL NOT NULL,
                    memory REAL NOT NULL,
                    processes INTEGER NOT NULL,
                    connections INTEGER NOT NULL
                );
                """
            )

    def add_event(self, event: dict) -> dict:
        with self.lock, self.connect() as db:
            cursor = db.execute(
                """
                INSERT INTO events
                (timestamp, category, event_type, source, severity, score, title, summary, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["timestamp"],
                    event["category"],
                    event["event_type"],
                    event["source"],
                    event["severity"],
                    event["score"],
                    event["title"],
                    event["summary"],
                    json.dumps(event.get("metadata", {})),
                ),
            )
            event["id"] = cursor.lastrowid
        return event

    def list_events(self, limit: int = 100) -> list[dict]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._event_from_row(row) for row in rows]

    def add_snapshot(self, snapshot: dict):
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO system_snapshots (timestamp, cpu, memory, processes, connections)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    snapshot["timestamp"],
                    snapshot["cpu"],
                    snapshot["memory"],
                    snapshot["processes"],
                    snapshot["connections"],
                ),
            )

    def latest_snapshots(self, limit: int = 30) -> list[dict]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM system_snapshots ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def clear_events(self):
        with self.connect() as db:
            db.execute("DELETE FROM events")

    @staticmethod
    def _event_from_row(row) -> dict:
        event = dict(row)
        event["metadata"] = json.loads(event["metadata"])
        return event


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

