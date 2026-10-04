from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class SQLiteStore:
    """Non-secret KeyGuard state.

    This schema intentionally has no column capable of storing a provider secret.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self.connection() as db:
            db.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS credentials (
                    id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    name TEXT NOT NULL,
                    masked_hint TEXT NOT NULL,
                    threshold REAL,
                    status TEXT NOT NULL DEFAULT 'healthy',
                    paused INTEGER NOT NULL DEFAULT 0,
                    auto_protect INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    credential_id TEXT,
                    kind TEXT NOT NULL,
                    detail_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
                );
                """
            )

    def create_credential(
        self,
        *,
        credential_id: str,
        provider: str,
        name: str,
        masked_hint: str,
        threshold: float | None,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connection() as db:
            db.execute(
                """
                INSERT INTO credentials
                    (id, provider, name, masked_hint, threshold, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (credential_id, provider, name, masked_hint, threshold, now, now),
            )
        return self.get_credential(credential_id)

    def list_credentials(self) -> list[dict[str, Any]]:
        with self.connection() as db:
            rows = db.execute(
                "SELECT * FROM credentials ORDER BY created_at, id"
            ).fetchall()
        return [self._credential(row) for row in rows]

    def get_credential(self, credential_id: str) -> dict[str, Any]:
        with self.connection() as db:
            row = db.execute(
                "SELECT * FROM credentials WHERE id = ?", (credential_id,)
            ).fetchone()
        if row is None:
            raise KeyError(credential_id)
        return self._credential(row)

    def update_credential(
        self, credential_id: str, values: dict[str, Any]
    ) -> dict[str, Any]:
        allowed = {"provider", "name", "threshold", "status", "paused", "auto_protect"}
        changes = {key: value for key, value in values.items() if key in allowed}
        if not changes:
            return self.get_credential(credential_id)
        changes["updated_at"] = utc_now()
        assignments = ", ".join(f"{key} = ?" for key in changes)
        with self.connection() as db:
            cursor = db.execute(
                f"UPDATE credentials SET {assignments} WHERE id = ?",
                (*changes.values(), credential_id),
            )
            if cursor.rowcount == 0:
                raise KeyError(credential_id)
        return self.get_credential(credential_id)

    def delete_credential(self, credential_id: str) -> None:
        with self.connection() as db:
            cursor = db.execute(
                "DELETE FROM credentials WHERE id = ?", (credential_id,)
            )
            if cursor.rowcount == 0:
                raise KeyError(credential_id)

    def record_event(
        self, credential_id: str | None, kind: str, detail: dict[str, Any]
    ) -> dict[str, Any]:
        created_at = utc_now()
        with self.connection() as db:
            cursor = db.execute(
                """
                INSERT INTO events (credential_id, kind, detail_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (credential_id, kind, json.dumps(detail, sort_keys=True), created_at),
            )
            event_id = cursor.lastrowid
        return {
            "id": event_id,
            "credential_id": credential_id,
            "kind": kind,
            "detail": detail,
            "created_at": created_at,
        }

    def history(self, credential_id: str) -> list[dict[str, Any]]:
        self.get_credential(credential_id)
        with self.connection() as db:
            rows = db.execute(
                """
                SELECT id, credential_id, kind, detail_json, created_at
                FROM events WHERE credential_id = ? ORDER BY id DESC
                """,
                (credential_id,),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "credential_id": row["credential_id"],
                "kind": row["kind"],
                "detail": json.loads(row["detail_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    @staticmethod
    def _credential(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "provider": row["provider"],
            "name": row["name"],
            "masked_hint": row["masked_hint"],
            "threshold": row["threshold"],
            "status": row["status"],
            "paused": bool(row["paused"]),
            "auto_protect": bool(row["auto_protect"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
