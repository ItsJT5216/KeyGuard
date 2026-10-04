from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .vault import Vault


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class Store:
    def __init__(self, path: Path, vault: Vault) -> None:
        self.path = path
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path.parent.chmod(0o700)
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self.vault = vault
        self._migrate()
        try:
            self.path.chmod(0o600)
        except FileNotFoundError:
            pass

    def close(self) -> None:
        self._db.close()

    def _migrate(self) -> None:
        with self._db:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS credentials (
                    id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    name TEXT NOT NULL,
                    masked_identifier TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'watching',
                    auto_protect INTEGER NOT NULL DEFAULT 0,
                    threshold REAL,
                    paused INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    credential_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    result TEXT NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
                )
                """
            )

    @staticmethod
    def _public(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "provider": row["provider"],
            "name": row["name"],
            "masked_identifier": row["masked_identifier"],
            "status": row["status"],
            "auto_protect": bool(row["auto_protect"]),
            "threshold": row["threshold"],
            "paused": bool(row["paused"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list_credentials(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM credentials ORDER BY provider COLLATE NOCASE, name COLLATE NOCASE"
            ).fetchall()
        return [self._public(row) for row in rows]

    def get_credential(self, credential_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM credentials WHERE id = ?", (credential_id,)
            ).fetchone()
        return self._public(row) if row else None

    def create_credential(
        self,
        *,
        provider: str,
        name: str,
        secret: str,
        threshold: float | None,
        auto_protect: bool,
    ) -> dict[str, Any]:
        credential_id = str(uuid.uuid4())
        now = utc_now()
        masked = f"••••{secret[-4:]}" if len(secret) >= 4 else "••••"
        self.vault.set(credential_id, secret)
        try:
            with self._lock, self._db:
                self._db.execute(
                    """
                    INSERT INTO credentials
                    (id, provider, name, masked_identifier, auto_protect, threshold, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        credential_id,
                        provider,
                        name,
                        masked,
                        int(auto_protect),
                        threshold,
                        now,
                        now,
                    ),
                )
                self._record_event_locked(
                    credential_id, "credential_added", "success", {}
                )
        except Exception:
            self.vault.delete(credential_id)
            raise
        created = self.get_credential(credential_id)
        if created is None:
            raise RuntimeError("Credential record was not persisted")
        return created

    def update_credential(
        self, credential_id: str, values: dict[str, Any]
    ) -> dict[str, Any] | None:
        current = self.get_credential(credential_id)
        if current is None:
            return None

        secret = values.pop("api_key", None)
        old_secret: str | None = None
        if secret is not None:
            old_secret = self.vault.get(credential_id)
            self.vault.set(credential_id, secret)
            values["masked_identifier"] = (
                f"••••{secret[-4:]}" if len(secret) >= 4 else "••••"
            )

        provider = values.get("provider", current["provider"])
        name = values.get("name", current["name"])
        masked_identifier = values.get(
            "masked_identifier", current["masked_identifier"]
        )
        threshold = values.get("threshold", current["threshold"])
        auto_protect = values.get("auto_protect", current["auto_protect"])

        try:
            with self._lock, self._db:
                self._db.execute(
                    """
                    UPDATE credentials
                    SET provider = ?, name = ?, masked_identifier = ?, threshold = ?,
                        auto_protect = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        provider,
                        name,
                        masked_identifier,
                        threshold,
                        int(auto_protect),
                        utc_now(),
                        credential_id,
                    ),
                )
                self._record_event_locked(
                    credential_id, "credential_updated", "success", {}
                )
        except Exception:
            if secret is not None:
                if old_secret is None:
                    self.vault.delete(credential_id)
                else:
                    self.vault.set(credential_id, old_secret)
            raise
        return self.get_credential(credential_id)

    def delete_credential(self, credential_id: str) -> bool:
        current = self.get_credential(credential_id)
        if current is None:
            return False
        old_secret = self.vault.get(credential_id)
        self.vault.delete(credential_id)
        try:
            with self._lock, self._db:
                cursor = self._db.execute(
                    "DELETE FROM credentials WHERE id = ?", (credential_id,)
                )
        except Exception:
            if old_secret is not None:
                self.vault.set(credential_id, old_secret)
            raise
        return cursor.rowcount > 0

    def set_paused(self, credential_id: str, paused: bool) -> dict[str, Any] | None:
        status = "paused" if paused else "watching"
        with self._lock, self._db:
            cursor = self._db.execute(
                "UPDATE credentials SET paused = ?, status = ?, updated_at = ? WHERE id = ?",
                (int(paused), status, utc_now(), credential_id),
            )
            if cursor.rowcount:
                self._record_event_locked(
                    credential_id,
                    "monitoring_paused" if paused else "monitoring_resumed",
                    "success",
                    {},
                )
        return self.get_credential(credential_id) if cursor.rowcount else None

    def record_event(
        self,
        credential_id: str,
        event_type: str,
        result: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        if self.get_credential(credential_id) is None:
            return None
        with self._lock, self._db:
            event_id = self._record_event_locked(
                credential_id, event_type, result, details or {}
            )
        return self._event_by_id(event_id)

    def _record_event_locked(
        self, credential_id: str, event_type: str, result: str, details: dict[str, Any]
    ) -> int:
        cursor = self._db.execute(
            """
            INSERT INTO events (credential_id, event_type, result, details_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                credential_id,
                event_type,
                result,
                json.dumps(details, separators=(",", ":")),
                utc_now(),
            ),
        )
        return int(cursor.lastrowid)

    def _event_by_id(self, event_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM events WHERE id = ?", (event_id,)
            ).fetchone()
        return self._event_public(row) if row else None

    @staticmethod
    def _event_public(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "credential_id": row["credential_id"],
            "event_type": row["event_type"],
            "result": row["result"],
            "details": json.loads(row["details_json"]),
            "created_at": row["created_at"],
        }

    def history(self, credential_id: str) -> list[dict[str, Any]] | None:
        if self.get_credential(credential_id) is None:
            return None
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM events WHERE credential_id = ? ORDER BY id DESC",
                (credential_id,),
            ).fetchall()
        return [self._event_public(row) for row in rows]

    def providers(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT DISTINCT provider FROM credentials ORDER BY provider COLLATE NOCASE"
            ).fetchall()
        return [{"id": row["provider"], "capabilities": []} for row in rows]
