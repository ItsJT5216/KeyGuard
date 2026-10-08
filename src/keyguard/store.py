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
        self._recover_incomplete_credentials()
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
                    provider_metadata_json TEXT NOT NULL DEFAULT '{}',
                    protection_action TEXT NOT NULL DEFAULT 'notify_only',
                    polling_config_json TEXT NOT NULL DEFAULT '{}',
                    paused INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            columns = {
                row["name"]
                for row in self._db.execute("PRAGMA table_info(credentials)").fetchall()
            }
            if "provider_metadata_json" not in columns:
                self._db.execute(
                    "ALTER TABLE credentials ADD COLUMN provider_metadata_json TEXT NOT NULL DEFAULT '{}'"
                )
            if "protection_action" not in columns:
                self._db.execute(
                    "ALTER TABLE credentials ADD COLUMN protection_action TEXT NOT NULL DEFAULT 'notify_only'"
                )
            if "polling_config_json" not in columns:
                self._db.execute(
                    "ALTER TABLE credentials ADD COLUMN polling_config_json TEXT NOT NULL DEFAULT '{}'"
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
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS usage_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    credential_id TEXT NOT NULL,
                    checked_at TEXT NOT NULL,
                    used REAL,
                    configured_limit REAL,
                    remaining REAL,
                    unit TEXT,
                    success INTEGER NOT NULL,
                    error_code TEXT,
                    provider_status_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
                )
                """
            )
            snapshot_columns = {
                row["name"]
                for row in self._db.execute(
                    "PRAGMA table_info(usage_snapshots)"
                ).fetchall()
            }
            if "provider_status_json" not in snapshot_columns:
                self._db.execute(
                    "ALTER TABLE usage_snapshots ADD COLUMN "
                    "provider_status_json TEXT NOT NULL DEFAULT '{}'"
                )
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS scheduler_state (
                    credential_id TEXT PRIMARY KEY,
                    last_check_at TEXT,
                    next_check_at TEXT,
                    current_interval_seconds INTEGER,
                    polling_tier TEXT,
                    consecutive_failures INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
                )
                """
            )

    def _recover_incomplete_credentials(self) -> None:
        with self._lock:
            rows = self._db.execute(
                "SELECT id FROM credentials WHERE status = 'provisioning'"
            ).fetchall()
            for row in rows:
                credential_id = row["id"]
                secret = self.vault.get(credential_id)
                with self._db:
                    if secret is None:
                        self._db.execute(
                            "DELETE FROM credentials WHERE id = ?", (credential_id,)
                        )
                    else:
                        self._db.execute(
                            "UPDATE credentials SET status = 'watching', updated_at = ? WHERE id = ?",
                            (utc_now(), credential_id),
                        )
                        self._record_event_locked(
                            credential_id, "credential_recovered", "success", {}
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
            "provider_metadata": json.loads(row["provider_metadata_json"]),
            "protection_action": row["protection_action"],
            "polling_config": json.loads(row["polling_config_json"]),
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
        provider_metadata: dict[str, Any] | None = None,
        protection_action: str = "notify_only",
        polling_config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        credential_id = str(uuid.uuid4())
        now = utc_now()
        masked = f"••••{secret[-4:]}" if len(secret) > 4 else "••••"
        with self._lock:
            with self._db:
                self._db.execute(
                    """
                    INSERT INTO credentials
                    (id, provider, name, masked_identifier, status, auto_protect,
                     threshold, provider_metadata_json, protection_action,
                     polling_config_json,
                     created_at, updated_at)
                    VALUES (?, ?, ?, ?, 'provisioning', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        credential_id,
                        provider,
                        name,
                        masked,
                        int(auto_protect),
                        threshold,
                        json.dumps(provider_metadata or {}, separators=(",", ":")),
                        protection_action,
                        json.dumps(polling_config or {}, separators=(",", ":")),
                        now,
                        now,
                    ),
                )
            try:
                self.vault.set(credential_id, secret)
            except Exception:
                with self._db:
                    self._db.execute(
                        "DELETE FROM credentials WHERE id = ?", (credential_id,)
                    )
                raise
            try:
                with self._db:
                    self._db.execute(
                        "UPDATE credentials SET status = 'watching', updated_at = ? WHERE id = ?",
                        (utc_now(), credential_id),
                    )
                    self._record_event_locked(
                        credential_id, "credential_added", "success", {}
                    )
            except Exception:
                try:
                    self.vault.delete(credential_id)
                except Exception as cleanup_error:
                    with self._db:
                        self._db.execute(
                            "UPDATE credentials SET status = 'cleanup_required', updated_at = ? WHERE id = ?",
                            (utc_now(), credential_id),
                        )
                    raise RuntimeError(
                        "Credential creation failed; cleanup remains tracked"
                    ) from cleanup_error
                with self._db:
                    self._db.execute(
                        "DELETE FROM credentials WHERE id = ?", (credential_id,)
                    )
                raise
            row = self._db.execute(
                "SELECT * FROM credentials WHERE id = ?", (credential_id,)
            ).fetchone()
        if row is None:
            raise RuntimeError("Credential record was not persisted")
        return self._public(row)

    def update_credential(
        self, credential_id: str, values: dict[str, Any]
    ) -> dict[str, Any] | None:
        values = dict(values)
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM credentials WHERE id = ?", (credential_id,)
            ).fetchone()
            if row is None:
                return None
            current = self._public(row)
            secret = values.pop("api_key", None)
            old_secret: str | None = None
            if secret is not None:
                old_secret = self.vault.get(credential_id)
                self.vault.set(credential_id, secret)
                values["masked_identifier"] = (
                    f"••••{secret[-4:]}" if len(secret) > 4 else "••••"
                )
            try:
                with self._db:
                    self._db.execute(
                        """
                        UPDATE credentials
                        SET provider = ?, name = ?, masked_identifier = ?, threshold = ?,
                            auto_protect = ?, provider_metadata_json = ?,
                            protection_action = ?, polling_config_json = ?,
                            updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            values.get("provider", current["provider"]),
                            values.get("name", current["name"]),
                            values.get(
                                "masked_identifier", current["masked_identifier"]
                            ),
                            values.get("threshold", current["threshold"]),
                            int(values.get("auto_protect", current["auto_protect"])),
                            json.dumps(
                                values.get(
                                    "provider_metadata", current["provider_metadata"]
                                ),
                                separators=(",", ":"),
                            ),
                            values.get(
                                "protection_action", current["protection_action"]
                            ),
                            json.dumps(
                                values.get("polling_config", current["polling_config"]),
                                separators=(",", ":"),
                            ),
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
            updated = self._db.execute(
                "SELECT * FROM credentials WHERE id = ?", (credential_id,)
            ).fetchone()
        return self._public(updated) if updated else None

    def delete_credential(self, credential_id: str) -> bool:
        with self._lock:
            row = self._db.execute(
                "SELECT id FROM credentials WHERE id = ?", (credential_id,)
            ).fetchone()
            if row is None:
                return False
            old_secret = self.vault.get(credential_id)
            self.vault.delete(credential_id)
            try:
                with self._db:
                    cursor = self._db.execute(
                        "DELETE FROM credentials WHERE id = ?", (credential_id,)
                    )
            except Exception:
                if old_secret is not None:
                    self.vault.set(credential_id, old_secret)
                raise
            return cursor.rowcount > 0

    def get_secret(self, credential_id: str) -> str | None:
        with self._lock:
            exists = self._db.execute(
                "SELECT 1 FROM credentials WHERE id = ?", (credential_id,)
            ).fetchone()
            if exists is None:
                return None
            return self.vault.get(credential_id)

    def record_usage_snapshot(
        self, credential_id: str, snapshot: dict[str, Any]
    ) -> None:
        with self._lock, self._db:
            self._db.execute(
                """
                INSERT INTO usage_snapshots
                    (credential_id, checked_at, used, configured_limit, remaining,
                     unit, success, error_code, provider_status_json)
                VALUES (?, ?, ?, ?, ?, ?, 1, NULL, ?)
                """,
                (
                    credential_id,
                    snapshot["checked_at"],
                    snapshot["used"],
                    snapshot.get("limit"),
                    snapshot.get("remaining"),
                    snapshot["unit"],
                    json.dumps(
                        snapshot.get("provider_status", {}), separators=(",", ":")
                    ),
                ),
            )

    def usage_history(self, credential_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                """
                SELECT checked_at, used, configured_limit, remaining, unit, success,
                       error_code, provider_status_json
                FROM usage_snapshots WHERE credential_id = ? ORDER BY id DESC
                """,
                (credential_id,),
            ).fetchall()
        history = []
        for row in rows:
            item = dict(row)
            item["provider_status"] = json.loads(item.pop("provider_status_json"))
            history.append(item)
        return history

    def dashboard_state(self, credential_id: str) -> dict[str, Any]:
        """Return safe, derived live state for the thin dashboard client."""
        usage = self.usage_history(credential_id)
        latest = usage[0] if usage else None
        burn_rate: float | None = None
        if len(usage) > 1:
            current, previous = usage[0], usage[1]
            current_used = current.get("used")
            previous_used = previous.get("used")
            if current_used is not None and previous_used is not None:
                elapsed = (
                    datetime.fromisoformat(current["checked_at"])
                    - datetime.fromisoformat(previous["checked_at"])
                ).total_seconds()
                delta = float(current_used) - float(previous_used)
                if elapsed > 0 and delta > 0:
                    burn_rate = delta / elapsed

        latest_usage = None
        if latest is not None:
            limit = latest.get("configured_limit")
            used = latest.get("used")
            percent_consumed = None
            if limit not in (None, 0) and used is not None:
                percent_consumed = max(
                    0.0, min(float(used) / float(limit) * 100, 100.0)
                )
            latest_usage = {
                "checked_at": latest["checked_at"],
                "used": used,
                "limit": limit,
                "remaining": latest.get("remaining"),
                "unit": latest.get("unit"),
                "percent_consumed": percent_consumed,
                "provider_status": latest.get("provider_status", {}),
            }

        events = self.history(credential_id) or []
        last_action = next(
            (event for event in events if event["event_type"] == "protection_action"),
            None,
        )
        return {
            "usage": latest_usage,
            "burn_rate_per_second": burn_rate,
            "last_action": last_action,
        }

    def get_scheduler_state(self, credential_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM scheduler_state WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()
        return dict(row) if row else None

    def set_scheduler_state(
        self,
        credential_id: str,
        *,
        last_check_at: str | None,
        next_check_at: str | None,
        current_interval_seconds: int | None,
        polling_tier: str | None,
        consecutive_failures: int,
    ) -> None:
        with self._lock, self._db:
            self._db.execute(
                """
                INSERT INTO scheduler_state
                    (credential_id, last_check_at, next_check_at,
                     current_interval_seconds, polling_tier, consecutive_failures)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(credential_id) DO UPDATE SET
                    last_check_at = excluded.last_check_at,
                    next_check_at = excluded.next_check_at,
                    current_interval_seconds = excluded.current_interval_seconds,
                    polling_tier = excluded.polling_tier,
                    consecutive_failures = excluded.consecutive_failures
                """,
                (
                    credential_id,
                    last_check_at,
                    next_check_at,
                    current_interval_seconds,
                    polling_tier,
                    consecutive_failures,
                ),
            )

    def schedule_now(self, credential_id: str) -> None:
        state = self.get_scheduler_state(credential_id) or {}
        self.set_scheduler_state(
            credential_id,
            last_check_at=state.get("last_check_at"),
            next_check_at=utc_now(),
            current_interval_seconds=0,
            polling_tier="due",
            consecutive_failures=int(state.get("consecutive_failures", 0)),
        )

    def due_credentials(self, now: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                """
                SELECT c.*
                FROM credentials AS c
                LEFT JOIN scheduler_state AS s ON s.credential_id = c.id
                WHERE c.paused = 0
                  AND c.status NOT IN ('disabled', 'cleanup_required', 'provisioning')
                  AND (s.next_check_at IS NULL OR s.next_check_at <= ?)
                ORDER BY COALESCE(s.next_check_at, c.created_at), c.id
                """,
                (now,),
            ).fetchall()
        return [self._public(row) for row in rows]

    def next_scheduled_check(self) -> str | None:
        with self._lock:
            row = self._db.execute(
                """
                SELECT MIN(s.next_check_at) AS next_check_at
                FROM scheduler_state AS s
                JOIN credentials AS c ON c.id = s.credential_id
                WHERE c.paused = 0
                  AND c.status NOT IN ('disabled', 'cleanup_required', 'provisioning')
                  AND s.next_check_at IS NOT NULL
                """
            ).fetchone()
        return row["next_check_at"] if row else None

    def set_runtime_status(
        self, credential_id: str, status: str
    ) -> dict[str, Any] | None:
        with self._lock, self._db:
            cursor = self._db.execute(
                "UPDATE credentials SET status = ?, updated_at = ? WHERE id = ?",
                (status, utc_now(), credential_id),
            )
        return self.get_credential(credential_id) if cursor.rowcount else None

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
        with self._lock, self._db:
            exists = self._db.execute(
                "SELECT 1 FROM credentials WHERE id = ?", (credential_id,)
            ).fetchone()
            if exists is None:
                return None
            event_id = self._record_event_locked(
                credential_id, event_type, result, details or {}
            )
            row = self._db.execute(
                "SELECT * FROM events WHERE id = ?", (event_id,)
            ).fetchone()
        return self._event_public(row) if row else None

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
        with self._lock:
            exists = self._db.execute(
                "SELECT 1 FROM credentials WHERE id = ?", (credential_id,)
            ).fetchone()
            if exists is None:
                return None
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
