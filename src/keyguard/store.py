from __future__ import annotations

import json
import logging
import secrets
import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .vault import Vault

LOGGER = logging.getLogger("keyguard")


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def checked_at_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


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
                    notifications_muted INTEGER NOT NULL DEFAULT 0,
                    threshold REAL,
                    starting_allowance REAL,
                    starting_allowance_unit TEXT,
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
            if "notifications_muted" not in columns:
                self._db.execute(
                    "ALTER TABLE credentials ADD COLUMN "
                    "notifications_muted INTEGER NOT NULL DEFAULT 0"
                )
            if "starting_allowance" not in columns:
                self._db.execute(
                    "ALTER TABLE credentials ADD COLUMN starting_allowance REAL"
                )
            if "starting_allowance_unit" not in columns:
                self._db.execute(
                    "ALTER TABLE credentials ADD COLUMN starting_allowance_unit TEXT"
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
                    period_start TEXT,
                    period_end TEXT,
                    expires_at TEXT,
                    success INTEGER NOT NULL,
                    error_code TEXT,
                    provider_status_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
                )
                """
            )
            self._db.execute(
                """
                CREATE INDEX IF NOT EXISTS usage_snapshots_credential_id_id
                ON usage_snapshots (credential_id, id DESC)
                """
            )
            self._db.execute(
                """
                CREATE INDEX IF NOT EXISTS events_credential_type_id
                ON events (credential_id, event_type, id DESC)
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
            if "period_start" not in snapshot_columns:
                self._db.execute(
                    "ALTER TABLE usage_snapshots ADD COLUMN period_start TEXT"
                )
            if "period_end" not in snapshot_columns:
                self._db.execute(
                    "ALTER TABLE usage_snapshots ADD COLUMN period_end TEXT"
                )
            if "expires_at" not in snapshot_columns:
                self._db.execute(
                    "ALTER TABLE usage_snapshots ADD COLUMN expires_at TEXT"
                )
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS scheduler_state (
                    credential_id TEXT PRIMARY KEY,
                    last_check_at TEXT,
                    next_check_at TEXT,
                    current_interval_seconds INTEGER,
                    polling_tier TEXT,
                    notification_tier_group TEXT,
                    consecutive_failures INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
                )
                """
            )
            scheduler_columns = {
                row["name"]
                for row in self._db.execute(
                    "PRAGMA table_info(scheduler_state)"
                ).fetchall()
            }
            if "notification_tier_group" not in scheduler_columns:
                self._db.execute(
                    "ALTER TABLE scheduler_state ADD COLUMN notification_tier_group TEXT"
                )
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS credential_rotation_recovery (
                    credential_id TEXT PRIMARY KEY,
                    previous_status TEXT NOT NULL,
                    backup_credential_id TEXT NOT NULL,
                    had_previous_secret INTEGER NOT NULL,
                    identity_changed INTEGER NOT NULL DEFAULT 0,
                    stage TEXT NOT NULL,
                    FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
                )
                """
            )
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS notification_config (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    server_url TEXT NOT NULL,
                    topic TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                )
                """
            )
            default_topic = f"keyguard-{secrets.token_urlsafe(18)}"
            self._db.execute(
                """
                INSERT OR IGNORE INTO notification_config
                    (singleton, server_url, topic, enabled, updated_at)
                VALUES (1, 'https://ntfy.sh', ?, 0, ?)
                """,
                (default_topic, utc_now()),
            )

    def _recover_incomplete_credentials(self) -> None:
        with self._lock:
            rows = self._db.execute(
                """
                SELECT c.id, c.status, r.previous_status, r.backup_credential_id,
                       r.had_previous_secret, r.identity_changed, r.stage
                FROM credentials AS c
                LEFT JOIN credential_rotation_recovery AS r
                    ON r.credential_id = c.id
                WHERE c.status IN ('provisioning', 'cleanup_required')
                """
            ).fetchall()
            for row in rows:
                credential_id = row["id"]
                if row["status"] == "cleanup_required":
                    try:
                        self.vault.delete(credential_id)
                    except RuntimeError:
                        LOGGER.warning(
                            "Credential cleanup remains pending for %s",
                            credential_id,
                        )
                        continue
                    with self._db:
                        self._db.execute(
                            "DELETE FROM credentials WHERE id = ?", (credential_id,)
                        )
                    continue
                if row["previous_status"] is not None:
                    try:
                        if row["stage"] == "committed_cleanup":
                            self._finish_committed_rotation_locked(row)
                        else:
                            self._rollback_rotation_locked(row)
                    except RuntimeError:
                        LOGGER.warning(
                            "Credential rotation recovery remains pending for %s",
                            credential_id,
                        )
                    continue
                try:
                    secret = self.vault.get(credential_id)
                except RuntimeError:
                    LOGGER.warning(
                        "Credential provisioning recovery remains pending for %s",
                        credential_id,
                    )
                    continue
                with self._db:
                    if secret is None:
                        self._db.execute(
                            "DELETE FROM credentials WHERE id = ?", (credential_id,)
                        )
                    else:
                        masked = (
                            f"••••{secret[-4:]}" if len(secret) > 4 else "••••"
                        )
                        self._db.execute(
                            """
                            UPDATE credentials
                            SET status = 'watching', masked_identifier = ?, updated_at = ?
                            WHERE id = ?
                            """,
                            (masked, utc_now(), credential_id),
                        )
                        self._record_event_locked(
                            credential_id, "credential_recovered", "success", {}
                        )

    def _rotation_recovery_row_locked(
        self, credential_id: str
    ) -> sqlite3.Row | None:
        return self._db.execute(
            """
            SELECT c.id, c.status, r.previous_status, r.backup_credential_id,
                   r.had_previous_secret, r.identity_changed, r.stage
            FROM credentials AS c
            JOIN credential_rotation_recovery AS r
                ON r.credential_id = c.id
            WHERE c.id = ?
            """,
            (credential_id,),
        ).fetchone()

    def _complete_rotation_recovery_locked(
        self, recovery: sqlite3.Row, event_type: str
    ) -> None:
        credential_id = recovery["id"]
        with self._db:
            self._db.execute(
                "UPDATE credentials SET status = ?, updated_at = ? WHERE id = ?",
                (recovery["previous_status"], utc_now(), credential_id),
            )
            self._db.execute(
                "DELETE FROM credential_rotation_recovery WHERE credential_id = ?",
                (credential_id,),
            )
            self._record_event_locked(
                credential_id,
                event_type,
                "success",
                {
                    "credential_identity_changed": bool(
                        recovery["identity_changed"]
                    )
                },
            )

    def _delete_rotation_backup_locked(self, recovery: sqlite3.Row) -> None:
        if recovery["had_previous_secret"]:
            self.vault.delete(recovery["backup_credential_id"])

    def _finish_committed_rotation_locked(self, recovery: sqlite3.Row) -> None:
        self._delete_rotation_backup_locked(recovery)
        self._complete_rotation_recovery_locked(recovery, "credential_updated")

    def _rollback_rotation_locked(self, recovery: sqlite3.Row) -> None:
        credential_id = recovery["id"]
        if recovery["stage"] != "rollback_cleanup":
            if recovery["had_previous_secret"]:
                backup = self.vault.get(recovery["backup_credential_id"])
                if backup is None:
                    if recovery["stage"] != "backup_pending":
                        raise RuntimeError("Credential rotation backup is unavailable")
                else:
                    self.vault.set(credential_id, backup)
            else:
                self.vault.delete(credential_id)
            with self._db:
                self._db.execute(
                    """
                    UPDATE credential_rotation_recovery
                    SET stage = 'rollback_cleanup'
                    WHERE credential_id = ?
                    """,
                    (credential_id,),
                )
        self._delete_rotation_backup_locked(recovery)
        self._complete_rotation_recovery_locked(
            recovery, "credential_rotation_rolled_back"
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
            "notifications_muted": bool(row["notifications_muted"]),
            "threshold": row["threshold"],
            "starting_allowance": row["starting_allowance"],
            "starting_allowance_unit": row["starting_allowance_unit"],
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
        starting_allowance: float | None = None,
        starting_allowance_unit: str | None = None,
        notifications_muted: bool = False,
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
                     notifications_muted, threshold, starting_allowance,
                     starting_allowance_unit,
                     provider_metadata_json, protection_action, polling_config_json,
                     created_at, updated_at)
                    VALUES (?, ?, ?, ?, 'provisioning', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        credential_id,
                        provider,
                        name,
                        masked,
                        int(auto_protect),
                        int(notifications_muted),
                        threshold,
                        starting_allowance,
                        starting_allowance_unit,
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
            if current["status"] in {"provisioning", "cleanup_required"}:
                raise ValueError(
                    "Credential recovery is pending; settings are unavailable"
                )
            secret = values.pop("api_key", None)
            original_status = current["status"]
            old_secret: str | None = None
            identity_changed = (
                values.get("provider", current["provider"]) != current["provider"]
                or values.get(
                    "provider_metadata", current["provider_metadata"]
                )
                != current["provider_metadata"]
            )
            if secret is not None:
                old_secret = self.vault.get(credential_id)
                backup_credential_id = (
                    f"{credential_id}:rotation-backup:{uuid.uuid4()}"
                )
                with self._db:
                    self._db.execute(
                        """
                        INSERT INTO credential_rotation_recovery
                            (credential_id, previous_status, backup_credential_id,
                             had_previous_secret, identity_changed, stage)
                        VALUES (?, ?, ?, ?, ?, 'backup_pending')
                        """,
                        (
                            credential_id,
                            original_status,
                            backup_credential_id,
                            int(old_secret is not None),
                            int(identity_changed),
                        ),
                    )
                    self._db.execute(
                        """
                        UPDATE credentials
                        SET status = 'provisioning', updated_at = ?
                        WHERE id = ?
                        """,
                        (utc_now(), credential_id),
                    )
                try:
                    if old_secret is not None:
                        self.vault.set(backup_credential_id, old_secret)
                    with self._db:
                        self._db.execute(
                            """
                            UPDATE credential_rotation_recovery
                            SET stage = 'backup_ready'
                            WHERE credential_id = ?
                            """,
                            (credential_id,),
                        )
                    self.vault.set(credential_id, secret)
                except Exception:
                    try:
                        recovery = self._rotation_recovery_row_locked(credential_id)
                        if recovery is not None:
                            self._rollback_rotation_locked(recovery)
                    except Exception as recovery_error:
                        raise RuntimeError(
                            "Credential update failed; recovery remains tracked"
                        ) from recovery_error
                    raise
                values["masked_identifier"] = (
                    f"••••{secret[-4:]}" if len(secret) > 4 else "••••"
                )
            try:
                with self._db:
                    self._db.execute(
                        """
                        UPDATE credentials
                        SET provider = ?, name = ?, masked_identifier = ?, threshold = ?,
                            starting_allowance = ?, starting_allowance_unit = ?,
                            auto_protect = ?,
                            notifications_muted = ?, provider_metadata_json = ?,
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
                            values.get(
                                "starting_allowance", current["starting_allowance"]
                            ),
                            values.get(
                                "starting_allowance_unit",
                                current["starting_allowance_unit"],
                            ),
                            int(values.get("auto_protect", current["auto_protect"])),
                            int(
                                values.get(
                                    "notifications_muted",
                                    current["notifications_muted"],
                                )
                            ),
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
                    self._db.execute(
                        """
                        UPDATE credential_rotation_recovery
                        SET stage = 'committed_cleanup'
                        WHERE credential_id = ?
                        """,
                        (credential_id,),
                    )
            except Exception:
                if secret is not None:
                    try:
                        recovery = self._rotation_recovery_row_locked(credential_id)
                        if recovery is not None:
                            self._rollback_rotation_locked(recovery)
                    except Exception as recovery_error:
                        raise RuntimeError(
                            "Credential update failed; recovery remains tracked"
                        ) from recovery_error
                raise
            if secret is not None:
                try:
                    recovery = self._rotation_recovery_row_locked(credential_id)
                    if recovery is not None:
                        self._finish_committed_rotation_locked(recovery)
                except Exception as recovery_error:
                    raise RuntimeError(
                        "Credential update committed; recovery cleanup remains tracked"
                    ) from recovery_error
            else:
                with self._db:
                    self._record_event_locked(
                        credential_id,
                        "credential_updated",
                        "success",
                        {"credential_identity_changed": identity_changed},
                    )
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
            with self._db:
                self._db.execute(
                    """
                    UPDATE credentials
                    SET status = 'cleanup_required', updated_at = ?
                    WHERE id = ?
                    """,
                    (utc_now(), credential_id),
                )
            self.vault.delete(credential_id)
            with self._db:
                cursor = self._db.execute(
                    "DELETE FROM credentials WHERE id = ?", (credential_id,)
                )
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
                     unit, period_start, period_end, expires_at, success, error_code,
                     provider_status_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, NULL, ?)
                """,
                (
                    credential_id,
                    snapshot["checked_at"],
                    snapshot["used"],
                    snapshot.get("limit"),
                    snapshot.get("remaining"),
                    snapshot["unit"],
                    snapshot.get("period_start"),
                    snapshot.get("period_end"),
                    snapshot.get("expires_at"),
                    json.dumps(
                        snapshot.get("provider_status", {}), separators=(",", ":")
                    ),
                ),
            )

    def usage_history(
        self,
        credential_id: str,
        *,
        limit: int | None = None,
        chronological: bool = False,
    ) -> list[dict[str, Any]]:
        with self._lock:
            statement = """
                SELECT checked_at, used, configured_limit, remaining, unit,
                       period_start, period_end, expires_at, success, error_code,
                       provider_status_json
                FROM usage_snapshots WHERE credential_id = ? ORDER BY id DESC
            """
            parameters: list[Any] = [credential_id]
            if limit is not None:
                statement += " LIMIT ?"
                parameters.append(limit)
            rows = self._db.execute(statement, parameters).fetchall()
        history = []
        for row in rows:
            item = dict(row)
            item["provider_status"] = json.loads(item.pop("provider_status_json"))
            history.append(item)
        if chronological:
            history.reverse()
            history.sort(key=lambda item: checked_at_time(item["checked_at"]))
            for item in history:
                item["checked_at"] = checked_at_time(item["checked_at"]).isoformat()
        return history

    def dashboard_state(self, credential_id: str) -> dict[str, Any]:
        """Return safe, derived live state for the thin dashboard client."""
        with self._lock:
            usage_rows = self._db.execute(
                """
                SELECT checked_at, used, configured_limit, remaining, unit,
                       period_start, period_end, expires_at, success, error_code,
                       provider_status_json
                FROM usage_snapshots
                WHERE credential_id = ?
                ORDER BY id DESC
                LIMIT 2
                """,
                (credential_id,),
            ).fetchall()
            action_row = self._db.execute(
                """
                SELECT * FROM events
                WHERE credential_id = ? AND event_type = 'protection_action'
                ORDER BY id DESC
                LIMIT 1
                """,
                (credential_id,),
            ).fetchone()
        usage = []
        for row in usage_rows:
            item = dict(row)
            item["provider_status"] = json.loads(item.pop("provider_status_json"))
            usage.append(item)
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
                if elapsed > 0 and delta >= 0:
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
                "period_start": latest.get("period_start"),
                "period_end": latest.get("period_end"),
                "expires_at": latest.get("expires_at"),
                "percent_consumed": percent_consumed,
                "provider_status": latest.get("provider_status", {}),
            }

        last_action = self._event_public(action_row) if action_row else None
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
        notification_tier_group: str | None = None,
    ) -> None:
        with self._lock, self._db:
            self._db.execute(
                """
                INSERT INTO scheduler_state
                    (credential_id, last_check_at, next_check_at,
                     current_interval_seconds, polling_tier, consecutive_failures,
                     notification_tier_group)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(credential_id) DO UPDATE SET
                    last_check_at = excluded.last_check_at,
                    next_check_at = excluded.next_check_at,
                    current_interval_seconds = excluded.current_interval_seconds,
                    polling_tier = excluded.polling_tier,
                    consecutive_failures = excluded.consecutive_failures,
                    notification_tier_group = excluded.notification_tier_group
                """,
                (
                    credential_id,
                    last_check_at,
                    next_check_at,
                    current_interval_seconds,
                    polling_tier,
                    consecutive_failures,
                    notification_tier_group,
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
            notification_tier_group=state.get("notification_tier_group"),
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
            existing = self._db.execute(
                "SELECT status FROM credentials WHERE id = ?", (credential_id,)
            ).fetchone()
            if existing is None:
                return None
            if existing["status"] in {"provisioning", "cleanup_required"}:
                raise ValueError(
                    "Credential recovery is pending; pause and resume are unavailable"
                )
            self._db.execute(
                "UPDATE credentials SET paused = ?, status = ?, updated_at = ? WHERE id = ?",
                (int(paused), status, utc_now(), credential_id),
            )
            self._record_event_locked(
                credential_id,
                "monitoring_paused" if paused else "monitoring_resumed",
                "success",
                {},
            )
        return self.get_credential(credential_id)

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

    def notify_only_alert_active(
        self,
        credential_id: str,
        threshold: float | None,
        credential_identity_revision: str,
    ) -> bool:
        """Return whether this automatic threshold crossing was delivered."""
        with self._lock:
            row = self._db.execute(
                """
                SELECT id, event_type, result, details_json
                FROM events
                WHERE credential_id = ?
                  AND (
                    (event_type = 'protection_action' AND result = 'notify_only')
                    OR (event_type = 'usage_checked' AND result = 'success')
                    OR (
                        event_type = 'protection_cancelled'
                        AND result = 'verification_below_threshold'
                    )
                  )
                ORDER BY id DESC
                LIMIT 1
                """,
                (credential_id,),
            ).fetchone()
        if (
            row is None
            or row["event_type"] != "protection_action"
            or row["result"] != "notify_only"
        ):
            return False
        details = json.loads(row["details_json"])
        if details.get("threshold") != threshold:
            return False
        legacy_event = (
            details.get("action") == "notify_only"
            and details.get("verified") is True
            and "trigger" not in details
            and "credential_identity_revision" not in details
        )
        if legacy_event:
            with self._lock:
                identity_updates = self._db.execute(
                    """
                    SELECT details_json
                    FROM events
                    WHERE credential_id = ?
                      AND event_type = 'credential_updated'
                      AND result = 'success'
                      AND id > ?
                    ORDER BY id
                    """,
                    (credential_id, row["id"]),
                ).fetchall()
            if any(
                json.loads(update["details_json"]).get(
                    "credential_identity_changed", True
                )
                for update in identity_updates
            ):
                return False
        if not legacy_event and (
            details.get("trigger") != "automatic_threshold"
            or details.get("credential_identity_revision")
            != credential_identity_revision
        ):
            return False
        with self._lock:
            deliveries = self._db.execute(
                """
                SELECT result, details_json
                FROM events
                WHERE credential_id = ?
                  AND event_type = 'notification_delivery'
                  AND id > ?
                ORDER BY id
                """,
                (credential_id, row["id"]),
            ).fetchall()
        matching_deliveries = [
            delivery
            for delivery in deliveries
            if json.loads(delivery["details_json"]).get("source_event_id")
            == row["id"]
        ]
        if not matching_deliveries:
            return True
        return any(
            delivery["result"] == "success"
            for delivery in matching_deliveries
        )

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

    def history(
        self, credential_id: str, *, limit: int | None = None
    ) -> list[dict[str, Any]] | None:
        with self._lock:
            exists = self._db.execute(
                "SELECT 1 FROM credentials WHERE id = ?", (credential_id,)
            ).fetchone()
            if exists is None:
                return None
            statement = "SELECT * FROM events WHERE credential_id = ? ORDER BY id DESC"
            parameters: list[Any] = [credential_id]
            if limit is not None:
                statement += " LIMIT ?"
                parameters.append(limit)
            rows = self._db.execute(statement, parameters).fetchall()
        return [self._event_public(row) for row in rows]

    def providers(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT DISTINCT provider FROM credentials ORDER BY provider COLLATE NOCASE"
            ).fetchall()
        return [{"id": row["provider"], "capabilities": []} for row in rows]

    def get_notification_delivery_config(self) -> dict[str, Any]:
        with self._lock:
            row = self._db.execute(
                "SELECT server_url, topic, enabled, updated_at "
                "FROM notification_config WHERE singleton = 1"
            ).fetchone()
            if row is None:
                raise RuntimeError("Notification configuration is unavailable")
            auth_token = self.vault.get("__notification_ntfy_auth__")
        return {
            "server_url": row["server_url"],
            "topic": row["topic"],
            "enabled": bool(row["enabled"]),
            "auth_token": auth_token,
            "updated_at": row["updated_at"],
        }

    def get_notification_config(self) -> dict[str, Any]:
        config = self.get_notification_delivery_config()
        auth_token = config.pop("auth_token")
        config["auth_configured"] = auth_token is not None
        return config

    def update_notification_config(self, values: dict[str, Any]) -> dict[str, Any]:
        secret_id = "__notification_ntfy_auth__"
        with self._lock:
            row = self._db.execute(
                "SELECT server_url, topic, enabled FROM notification_config "
                "WHERE singleton = 1"
            ).fetchone()
            if row is None:
                raise RuntimeError("Notification configuration is unavailable")
            previous_token = self.vault.get(secret_id)
            server_url = values.get("server_url", row["server_url"])
            topic = values.get("topic", row["topic"])
            enabled = values.get("enabled", bool(row["enabled"]))
            token_supplied = "auth_token" in values
            auth_token = values.get("auth_token")
            if (
                server_url != row["server_url"]
                and previous_token is not None
                and not token_supplied
            ):
                raise ValueError(
                    "auth_token must be replaced or cleared when server_url changes"
                )
            if token_supplied:
                if auth_token:
                    self.vault.set(secret_id, auth_token)
                else:
                    self.vault.delete(secret_id)
            try:
                with self._db:
                    self._db.execute(
                        """
                        UPDATE notification_config
                        SET server_url = ?, topic = ?, enabled = ?, updated_at = ?
                        WHERE singleton = 1
                        """,
                        (server_url, topic, int(enabled), utc_now()),
                    )
            except Exception:
                if token_supplied:
                    if previous_token is None:
                        self.vault.delete(secret_id)
                    else:
                        self.vault.set(secret_id, previous_token)
                raise
        return self.get_notification_config()


