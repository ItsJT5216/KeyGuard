from __future__ import annotations

import io
import json
import logging
import socket
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock, patch

from keyring.errors import PasswordDeleteError

from keyguard import cli
from keyguard.api import create_server
from keyguard.auth import (
    BOOTSTRAP_TTL_SECONDS,
    SessionAuthority,
    load_or_create_token,
    mint_bootstrap,
)
from keyguard.store import Store
from keyguard.vault import SERVICE_NAME, KeyringVault


class FakeVault:
    def __init__(self) -> None:
        self.secrets: dict[str, str] = {}

    def set(self, credential_id: str, secret: str) -> None:
        self.secrets[credential_id] = secret

    def get(self, credential_id: str) -> str | None:
        return self.secrets.get(credential_id)

    def delete(self, credential_id: str) -> None:
        self.secrets.pop(credential_id, None)


class BlockingVault(FakeVault):
    def __init__(self) -> None:
        super().__init__()
        self.block = False
        self.entered = threading.Event()
        self.release = threading.Event()

    def set(self, credential_id: str, secret: str) -> None:
        if self.block:
            self.entered.set()
            self.release.wait(timeout=2)
        super().set(credential_id, secret)


class CleanupFailVault(FakeVault):
    def delete(self, credential_id: str) -> None:
        raise RuntimeError("vault cleanup failed")


def authorize(server) -> str:
    bootstrap = mint_bootstrap("test-token-that-is-long-enough-123456")
    session = server.authority.exchange_bootstrap(bootstrap)
    assert session is not None
    return session


class FoundationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state.db"
        self.vault = FakeVault()
        self.store = Store(self.path, self.vault)

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def test_secret_lives_only_in_vault_and_public_record_survives_restart(
        self,
    ) -> None:
        secret = "sk-real-secret-value-1234"
        created = self.store.create_credential(
            provider="Example",
            name="Primary",
            secret=secret,
            threshold=10.0,
            auto_protect=True,
        )
        credential_id = created["id"]

        self.assertEqual(secret, self.vault.secrets[credential_id])
        self.assertNotIn("api_key", created)
        self.assertNotIn("secret", created)
        self.assertNotIn(secret.encode(), self.path.read_bytes())

        self.store.close()
        self.store = Store(self.path, self.vault)
        reopened = self.store.get_credential(credential_id)
        self.assertEqual("Primary", reopened["name"])
        self.assertNotIn("api_key", reopened)

    def test_existing_database_defaults_credentials_to_notifications_active(self) -> None:
        created = self.store.create_credential(
            provider="Example",
            name="Existing",
            secret="safe-secret",
            threshold=None,
            auto_protect=False,
        )
        self.store.close()
        with sqlite3.connect(self.path) as database:
            database.execute("ALTER TABLE credentials DROP COLUMN notifications_muted")
        self.store = Store(self.path, self.vault)

        reopened = self.store.get_credential(created["id"])

        self.assertIsNotNone(reopened)
        self.assertFalse(reopened["notifications_muted"])

    def test_existing_snapshot_table_adds_period_and_expiration_columns(self) -> None:
        self.store.close()
        with sqlite3.connect(self.path) as database:
            database.execute("ALTER TABLE usage_snapshots DROP COLUMN period_start")
            database.execute("ALTER TABLE usage_snapshots DROP COLUMN period_end")
            database.execute("ALTER TABLE usage_snapshots DROP COLUMN expires_at")

        self.store = Store(self.path, self.vault)

        columns = {
            row[1]
            for row in self.store._db.execute(
                "PRAGMA table_info(usage_snapshots)"
            ).fetchall()
        }
        self.assertIn("period_start", columns)
        self.assertIn("period_end", columns)
        self.assertIn("expires_at", columns)

    def test_parameterized_values_do_not_escape_sql(self) -> None:
        created = self.store.create_credential(
            provider="x'); DROP TABLE credentials; --",
            name="Injection-shaped label",
            secret="safe-secret",
            threshold=None,
            auto_protect=False,
        )
        self.assertEqual(1, len(self.store.list_credentials()))
        self.assertEqual(
            created["provider"], self.store.list_credentials()[0]["provider"]
        )

    def test_update_uses_fixed_fields_and_rotates_secret_without_leaking(self) -> None:
        created = self.store.create_credential(
            provider="Example",
            name="Primary",
            secret="old-secret",
            threshold=None,
            auto_protect=False,
        )
        updated = self.store.update_credential(
            created["id"],
            {
                "name": "Rotated",
                "api_key": "new-secret-9876",
                "not_a_column": "ignored",
            },
        )

        self.assertEqual("Rotated", updated["name"])
        self.assertEqual("••••9876", updated["masked_identifier"])
        self.assertEqual("new-secret-9876", self.vault.secrets[created["id"]])
        self.assertNotIn(b"new-secret-9876", self.path.read_bytes())

    def test_pause_resume_and_history_are_daemon_state(self) -> None:
        created = self.store.create_credential(
            provider="Example",
            name="Primary",
            secret="secret",
            threshold=None,
            auto_protect=False,
        )
        paused = self.store.set_paused(created["id"], True)
        self.assertTrue(paused["paused"])
        resumed = self.store.set_paused(created["id"], False)
        self.assertFalse(resumed["paused"])
        event_types = [
            event["event_type"] for event in self.store.history(created["id"])
        ]
        self.assertIn("monitoring_paused", event_types)
        self.assertIn("monitoring_resumed", event_types)
        self.assertEqual(1, len(self.store.history(created["id"], limit=1)))

    def test_api_access_log_redacts_query_string(self) -> None:
        token = "test-token-that-is-long-enough-123456"
        server = create_server(self.store, token, 0)
        session = authorize(server)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        secret = "query-secret-must-not-be-logged"
        capture = io.StringIO()
        handler = logging.StreamHandler(capture)
        logger = logging.getLogger("keyguard")
        original_level = logger.level
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)

        def send_raw(request: bytes) -> bytes:
            response = bytearray()
            with socket.create_connection(
                ("127.0.0.1", server.server_port), timeout=2
            ) as client:
                client.sendall(request)
                client.shutdown(socket.SHUT_WR)
                while chunk := client.recv(4096):
                    response.extend(chunk)
            return bytes(response)

        try:
            request = urllib.request.Request(
                f"{base}/api/credentials?api_key={secret}",
                headers={"Authorization": f"KeyGuard-Session {session}"},
            )
            with urllib.request.urlopen(request) as response:
                self.assertEqual(200, response.status)
                response.read()

            host = f"Host: 127.0.0.1:{server.server_port}\r\n".encode()
            raw_requests = {
                "repeated spaces": (
                    f"GET  /api/status?api_key={secret}-spaces HTTP/1.1\r\n".encode()
                    + host
                    + b"Connection: close\r\n\r\n"
                ),
                "tabs": (
                    f"GET\t/api/status?api_key={secret}-tabs\tHTTP/1.1\r\n".encode()
                    + host
                    + b"Connection: close\r\n\r\n"
                ),
                "http 0.9": f"GET /?api_key={secret}-http09\r\n".encode(),
                "parser error": (
                    f"GET /api/status?api_key={secret}-parser EXTRA HTTP/1.1\r\n".encode()
                    + host
                    + b"Connection: close\r\n\r\n"
                ),
                "malformed absolute target": (
                    f"GET //[/?api_key={secret}-absolute HTTP/1.1\r\n".encode()
                    + host
                    + b"Connection: close\r\n\r\n"
                ),
                "fragment": (
                    f"GET /api/status#{secret}-fragment HTTP/1.1\r\n".encode()
                    + host
                    + b"Connection: close\r\n\r\n"
                ),
            }
            for label, raw_request in raw_requests.items():
                with self.subTest(label=label):
                    send_raw(raw_request)

            log_output = capture.getvalue()
            self.assertIn("/api/credentials", log_output)
            self.assertIn("/api/status", log_output)
            self.assertNotIn(secret, log_output)
            self.assertNotIn("api_key=", log_output)
        finally:
            logger.removeHandler(handler)
            logger.setLevel(original_level)
            handler.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_api_never_returns_raw_secret_and_rejects_remote_origin(self) -> None:
        token = "test-token-that-is-long-enough-123456"
        server = create_server(self.store, token, 0)
        session = authorize(server)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        secret = "api-secret-never-returned"

        try:
            body = json.dumps(
                {
                    "provider": "Example",
                    "name": "Primary",
                    "api_key": secret,
                    "threshold": 10,
                    "auto_protect": True,
                }
            ).encode()
            request = urllib.request.Request(
                f"{base}/api/credentials",
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"KeyGuard-Session {session}",
                },
            )
            with urllib.request.urlopen(request) as response:
                created_payload = response.read()
            self.assertNotIn(secret.encode(), created_payload)
            created = json.loads(created_payload)["credential"]
            self.store.record_usage_snapshot(
                created["id"],
                {
                    "checked_at": "2026-10-08T10:00:00+00:00",
                    "used": 4,
                    "limit": 10,
                    "remaining": 6,
                    "unit": "credits",
                    "provider_status": {"scope": "test"},
                },
            )

            listing = urllib.request.Request(
                f"{base}/api/credentials",
                headers={"Authorization": f"KeyGuard-Session {session}"},
            )
            with urllib.request.urlopen(listing) as response:
                list_payload = response.read()
            self.assertNotIn(secret.encode(), list_payload)
            self.assertNotIn(b"api_key", list_payload)
            live = json.loads(list_payload)["credentials"][0]
            self.assertEqual(4, live["usage"]["used"])
            self.assertEqual(40, live["usage"]["percent_consumed"])
            self.assertEqual("test", live["usage"]["provider_status"]["scope"])

            rejected = urllib.request.Request(
                f"{base}/api/credentials",
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Origin": "https://attacker.example",
                    "Authorization": f"KeyGuard-Session {session}",
                },
            )
            with self.assertRaises(urllib.error.HTTPError) as context:
                urllib.request.urlopen(rejected)
            self.assertEqual(403, context.exception.code)
            context.exception.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_create_rejects_invalid_provider_configuration_as_client_error(
        self,
    ) -> None:
        token = "test-token-that-is-long-enough-123456"
        server = create_server(self.store, token, 0)
        session = authorize(server)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"

        try:
            request = urllib.request.Request(
                f"{base}/api/credentials",
                data=json.dumps(
                    {
                        "provider": "openrouter",
                        "name": "Missing key hash",
                        "api_key": "management-secret",
                        "protection_action": "disable",
                    }
                ).encode(),
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"KeyGuard-Session {session}",
                },
            )
            with self.assertRaises(urllib.error.HTTPError) as rejected:
                urllib.request.urlopen(request)
            self.assertEqual(422, rejected.exception.code)
            payload = json.loads(rejected.exception.read())
            self.assertEqual("PROVIDER_CONFIGURATION_ERROR", payload["error"]["code"])
            rejected.exception.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_keyring_vault_uses_secret_service_namespace(self) -> None:
        backend = MagicMock()
        vault = KeyringVault(backend)

        vault.set("credential-id", "raw-value")
        backend.set_password.assert_called_once_with(
            SERVICE_NAME, "credential:credential-id", "raw-value"
        )

    def test_keyring_delete_fails_closed_when_secret_remains(self) -> None:
        backend = MagicMock()
        backend.delete_password.side_effect = PasswordDeleteError("missing")
        backend.get_password.return_value = "still-present"
        vault = KeyringVault(backend)

        with self.assertRaisesRegex(RuntimeError, "could not delete"):
            vault.delete("credential-id")

    def test_four_character_secret_is_fully_masked(self) -> None:
        created = self.store.create_credential(
            provider="Example",
            name="Primary",
            secret="abcd",
            threshold=None,
            auto_protect=False,
        )
        self.assertEqual("••••", created["masked_identifier"])

    def test_auth_token_is_stable_and_owner_only(self) -> None:
        path = Path(self.temp.name) / "private" / "api-token"
        tokens: list[str] = []
        threads = [
            threading.Thread(target=lambda: tokens.append(load_or_create_token(path)))
            for _ in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)
        self.assertEqual(8, len(tokens))
        self.assertEqual(1, len(set(tokens)))
        self.assertEqual(tokens[0], load_or_create_token(path))
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        self.assertEqual(0o700, path.parent.stat().st_mode & 0o777)

    def test_api_preserves_secret_whitespace_exactly(self) -> None:
        token = "test-token-that-is-long-enough-123456"
        server = create_server(self.store, token, 0)
        session = authorize(server)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        secret = " leading-and-trailing-secret "
        try:
            request = urllib.request.Request(
                f"{base}/api/credentials",
                data=json.dumps(
                    {"provider": "Example", "name": "Primary", "api_key": secret}
                ).encode(),
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"KeyGuard-Session {session}",
                },
            )
            with urllib.request.urlopen(request) as response:
                created = json.loads(response.read())["credential"]
            self.assertEqual(secret, self.vault.secrets[created["id"]])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_foundation_schema_includes_snapshot_and_scheduler_state(self) -> None:
        tables = {
            row[0]
            for row in self.store._db.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        self.assertTrue(
            {"credentials", "events", "usage_snapshots", "scheduler_state"} <= tables
        )
        snapshot_columns = {
            row[1]
            for row in self.store._db.execute(
                "PRAGMA table_info(usage_snapshots)"
            ).fetchall()
        }
        self.assertIn("provider_status_json", snapshot_columns)
        self.assertIn("period_start", snapshot_columns)
        self.assertIn("period_end", snapshot_columns)
        self.assertIn("expires_at", snapshot_columns)
        indexes = {
            row[0]
            for row in self.store._db.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            ).fetchall()
        }
        self.assertIn("usage_snapshots_credential_id_id", indexes)
        self.assertIn("events_credential_type_id", indexes)

    def test_dashboard_state_uses_real_snapshots_and_last_protection_action(
        self,
    ) -> None:
        created = self.store.create_credential(
            provider="Example",
            name="Primary",
            secret="secret",
            threshold=15,
            auto_protect=True,
        )
        credential_id = created["id"]
        self.store.record_usage_snapshot(
            credential_id,
            {
                "checked_at": "2026-10-08T09:00:00+00:00",
                "used": 2,
                "limit": 20,
                "remaining": 18,
                "unit": "USD",
                "period_start": "2026-10-01T00:00:00+00:00",
                "period_end": "2026-11-01T00:00:00+00:00",
                "expires_at": "2027-12-31T23:59:59Z",
                "provider_status": {"limit_reset": "2026-11-01T00:00:00+00:00"},
            },
        )
        self.store.record_usage_snapshot(
            credential_id,
            {
                "checked_at": "2026-10-08T10:00:00+00:00",
                "used": 6,
                "limit": 20,
                "remaining": 14,
                "unit": "USD",
                "period_start": "2026-10-01T00:00:00+00:00",
                "period_end": "2026-11-01T00:00:00+00:00",
                "expires_at": "2027-12-31T23:59:59Z",
                "provider_status": {"limit_reset": "2026-11-01T00:00:00+00:00"},
            },
        )
        self.store.record_event(
            credential_id,
            "protection_action",
            "success",
            {"action": "disable"},
        )

        state = self.store.dashboard_state(credential_id)

        self.assertEqual(6, state["usage"]["used"])
        self.assertEqual(14, state["usage"]["remaining"])
        self.assertEqual(30, state["usage"]["percent_consumed"])
        self.assertEqual("2026-10-01T00:00:00+00:00", state["usage"]["period_start"])
        self.assertEqual("2026-11-01T00:00:00+00:00", state["usage"]["period_end"])
        self.assertEqual("2027-12-31T23:59:59Z", state["usage"]["expires_at"])
        history = self.store.usage_history(credential_id)
        self.assertEqual("2026-10-01T00:00:00+00:00", history[0]["period_start"])
        self.assertEqual("2026-11-01T00:00:00+00:00", history[0]["period_end"])
        self.assertEqual("2027-12-31T23:59:59Z", history[0]["expires_at"])
        self.assertEqual(
            "2026-11-01T00:00:00+00:00",
            state["usage"]["provider_status"]["limit_reset"],
        )
        self.assertAlmostEqual(4 / 3600, state["burn_rate_per_second"])
        self.assertEqual("protection_action", state["last_action"]["event_type"])
        self.assertEqual("success", state["last_action"]["result"])

        chart_history = self.store.usage_history(
            credential_id, limit=2, chronological=True
        )
        self.assertEqual(
            ["2026-10-08T09:00:00+00:00", "2026-10-08T10:00:00+00:00"],
            [item["checked_at"] for item in chart_history],
        )

        self.store.record_usage_snapshot(
            credential_id,
            {
                "checked_at": "2026-10-08T11:00:00+00:00",
                "used": 6,
                "limit": 20,
                "remaining": 14,
                "unit": "USD",
                "provider_status": {},
            },
        )
        self.assertEqual(
            0, self.store.dashboard_state(credential_id)["burn_rate_per_second"]
        )

    def test_api_uses_challenge_one_time_bootstrap_and_origin_scoped_session(
        self,
    ) -> None:
        token = "test-token-that-is-long-enough-123456"
        server = create_server(self.store, token, 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with self.assertRaises(urllib.error.HTTPError) as unauthorized:
                urllib.request.urlopen(f"{base}/api/status")
            self.assertEqual(401, unauthorized.exception.code)
            unauthorized.exception.close()

            nonce = "a" * 64
            with urllib.request.urlopen(
                f"{base}/api/challenge?nonce={nonce}"
            ) as response:
                challenge = json.loads(response.read())
            self.assertEqual(
                SessionAuthority(token).challenge(nonce), challenge["proof"]
            )

            bootstrap_token = mint_bootstrap(token)
            exchange = urllib.request.Request(
                f"{base}/api/session",
                data=b"",
                method="POST",
                headers={"Authorization": f"KeyGuard-Bootstrap {bootstrap_token}"},
            )
            with urllib.request.urlopen(exchange) as response:
                session = json.loads(response.read())["session_token"]

            with self.assertRaises(urllib.error.HTTPError) as reused:
                urllib.request.urlopen(exchange)
            self.assertEqual(401, reused.exception.code)
            reused.exception.close()

            bad_host = urllib.request.Request(
                f"{base}/api/status",
                headers={
                    "Authorization": f"KeyGuard-Session {session}",
                    "Host": "evil.example",
                },
            )
            with self.assertRaises(urllib.error.HTTPError) as rejected:
                urllib.request.urlopen(bad_host)
            self.assertEqual(421, rejected.exception.code)
            rejected.exception.close()

            status = urllib.request.Request(
                f"{base}/api/status",
                headers={"Authorization": f"KeyGuard-Session {session}"},
            )
            with urllib.request.urlopen(status) as response:
                self.assertEqual(200, response.status)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_dashboard_assets_are_daemon_served_with_strict_csp(self) -> None:
        server = create_server(self.store, "test-token-that-is-long-enough-123456", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with urllib.request.urlopen(f"{base}/") as response:
                page = response.read()
                policy = response.headers["Content-Security-Policy"]
            with urllib.request.urlopen(f"{base}/app.js") as response:
                script = response.read()
            with urllib.request.urlopen(f"{base}/style.css") as response:
                styles = response.read()

            self.assertIn(b'id="credentials"', page)
            self.assertIn(b"sortCredentials", script)
            self.assertIn(b"progress-track", styles)
            self.assertIn(b'input[type="checkbox"]', styles)
            self.assertIn(b"flex: 0 0 auto", styles)
            self.assertIn(b"width: auto", styles)
            self.assertIn("default-src 'self'", policy)
            self.assertIn("script-src 'self'", policy)
            self.assertIn("style-src 'self'", policy)
            self.assertNotIn("unsafe-inline", policy)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_bootstrap_rejects_expired_and_tampered_capabilities(self) -> None:
        token = "test-token-that-is-long-enough-123456"
        authority = SessionAuthority(token)
        expired = mint_bootstrap(token, issued_at=0)
        current = mint_bootstrap(token)
        prefix, signature = current.rsplit(".", 1)

        self.assertIsNone(authority.exchange_bootstrap(expired))
        self.assertIsNone(
            authority.exchange_bootstrap(
                f"{prefix}.{('0' if signature[0] != '0' else '1')}{signature[1:]}"
            )
        )
        self.assertGreater(BOOTSTRAP_TTL_SECONDS, 0)

    def test_usage_history_bounds_newest_rows_then_sorts_by_checked_at(self) -> None:
        created = self.store.create_credential(
            provider="Example",
            name="Out of order",
            secret="secret",
            threshold=15,
            auto_protect=False,
        )
        for used, checked_at in (
            (1, "2026-10-19T09:00:00+00:00"),
            (2, "2026-10-19T11:00:00+00:00"),
            (3, "2026-10-19T10:00:00+00:00"),
            (4, "2026-10-19T11:00:00"),
        ):
            self.store.record_usage_snapshot(
                created["id"],
                {
                    "checked_at": checked_at,
                    "used": used,
                    "limit": 20,
                    "remaining": 20 - used,
                    "unit": "USD",
                    "provider_status": {},
                },
            )

        self.assertEqual(
            [4, 3, 2, 1],
            [item["used"] for item in self.store.usage_history(created["id"])],
        )
        self.assertEqual(
            [3, 2, 4],
            [
                item["used"]
                for item in self.store.usage_history(
                    created["id"], limit=3, chronological=True
                )
            ],
        )
        self.assertEqual(
            "2026-10-19T11:00:00+00:00",
            self.store.usage_history(
                created["id"], limit=3, chronological=True
            )[-1]["checked_at"],
        )

    def test_dashboard_never_persists_owner_or_provider_secrets(self) -> None:
        script = (
            Path(__file__).parents[1] / "src" / "keyguard" / "dashboard" / "app.js"
        ).read_text()

        self.assertIn("sessionStorage", script)
        self.assertNotIn("localStorage", script)
        self.assertNotIn("document.cookie", script)
        self.assertNotIn('setItem("api_key"', script)
        self.assertIn(
            "protect.disabled = !(credential.available_actions || []).includes(", script
        )
        self.assertNotIn('credential.available_actions.join(", ")', script)
        self.assertNotIn("Math.random", script)
        self.assertIn("/api/credentials/${encodeURIComponent(id)}/${action}", script)
        self.assertIn(
            "/api/credentials/${encodeURIComponent(credential.id)}/history?limit=12",
            script,
        )
        self.assertIn("function usageSparkline(snapshots)", script)
        self.assertIn("const {events, usage = []}", script)
        self.assertIn('svg.setAttribute("role", "img")', script)
        self.assertIn("No usage history recorded yet.", script)
        self.assertIn("timestamp: Date.parse(item.checked_at)", script)
        self.assertIn("timestampSpan === 0", script)
        self.assertIn('details.addEventListener("keyguard:refresh-history"', script)
        self.assertIn('new Event("keyguard:refresh-history")', script)
        self.assertIn("refreshPending = refreshPending || force", script)
        self.assertIn("let globalMessageOwner = null", script)
        self.assertIn("const historyRefreshErrors = new Map()", script)
        self.assertIn(
            "function showMessage(value, isError = false, owner = null)", script
        )
        self.assertIn("globalMessageOwner = owner", script)
        self.assertIn(
            "function reportHistoryRefreshError(credentialId, error, panel)", script
        )
        self.assertIn("if (!panel.isConnected) return", script)
        self.assertIn("historyRefreshErrors.set(credentialId, record)", script)
        self.assertIn(
            "function clearHistoryRefreshError(credentialId, panel)", script
        )
        self.assertIn("globalMessageOwner === record.owner", script)
        self.assertIn("historyRefreshErrors.delete(credentialId)", script)
        self.assertIn(
            """if (loaded) {
        reportHistoryRefreshError(credential.id, error, details);
      } else {
        content.replaceChildren""",
            script,
        )
        self.assertIn("clearHistoryRefreshError(credential.id, details)", script)
        self.assertIn("const polling = {...(credential.polling_config || {})}", script)
        self.assertIn("background && hasActiveInteraction()", script)
        self.assertIn(
            'querySelector(".edit-form:not([hidden])") !== null', script
        )
        self.assertIn("article.dataset.credentialId = credential.id", script)
        self.assertIn('article.querySelector(":scope > details.history[open]")', script)
        self.assertIn("openHistoryByCredential.get(credential.id)", script)
        self.assertIn('activeElement?.closest("details.history")', script)
        self.assertIn("focusedHistoryElement?.isConnected", script)
        self.assertIn("focusedHistoryElement.focus({preventScroll: true})", script)
        self.assertIn('tier === "error_retry"', script)
        self.assertIn("credential.status)", script)
        self.assertIn('"action_failed"', script)
        self.assertIn("credential.burn_rate_per_second !== null", script)
        self.assertIn('credential.notifications_muted ? "Muted" : "Active"', script)
        self.assertIn("{notifications_muted: !credential.notifications_muted}", script)
        self.assertIn('method: "PATCH"', script)
        self.assertIn("credential.usage?.expires_at", script)
        self.assertIn('metric("Credits expire", daysUntil(usage?.expires_at))', script)
        self.assertIn(
            'metric("Limit resets", daysUntil(usage?.period_end, "Reset due"))',
            script,
        )
        self.assertIn('function daysUntil(value, elapsed = "Expired")', script)
        self.assertIn("return elapsed", script)

    def test_polling_editor_exposes_safety_margin_and_caps_jitter(self) -> None:
        script = (
            Path(__file__).parents[1] / "src" / "keyguard" / "dashboard" / "app.js"
        ).read_text()

        self.assertIn(
            '["safety_margin_seconds", "Safety margin (seconds)"]',
            script,
        )
        self.assertIn(
            '["jitter_fraction", "Jitter fraction (0–0.5)"]',
            script,
        )
        self.assertIn('if (name === "jitter_fraction") input.max = "0.5";', script)
        polling_fields = script.split("for (const name of [", 1)[1].split("]) {", 1)[0]
        self.assertIn('"safety_margin_seconds"', polling_fields)
        self.assertIn('"jitter_fraction"', polling_fields)

    def test_background_refresh_failure_preserves_last_known_dashboard_state(self) -> None:
        script = (
            Path(__file__).parents[1] / "src" / "keyguard" / "dashboard" / "app.js"
        ).read_text()

        self.assertIn("let backgroundRefreshError = null", script)
        self.assertIn("Unable to refresh daemon state: ${error.message}", script)
        self.assertIn("reportBackgroundRefreshError(error)", script)
        self.assertIn("error.status = response.status", script)
        self.assertIn("let foregroundRefreshPending = false", script)
        self.assertIn(
            "background && (hasActiveInteraction() || foregroundRefreshPending)",
            script,
        )
        self.assertIn(
            """if (sequence !== loadSequence) return;
    clearBackgroundRefreshError();
    if (background && hasActiveInteraction()) return;""",
            script,
        )
        self.assertIn("if (background && error.status !== 401)", script)
        self.assertIn("if (error.status === 401) clearBackgroundRefreshError()", script)
        self.assertIn(
            """if (!background && sequence === loadSequence) {
      foregroundRefreshPending = false;
    }""",
            script,
        )
        self.assertIn(
            "globalMessage.textContent === backgroundRefreshError", script
        )
        self.assertIn(
            """if (focusedHistoryElement?.isConnected) {
      focusedHistoryElement.focus({preventScroll: true});
    }
  } catch (error) {""",
            script,
        )
        self.assertIn(
            """if (background && error.status !== 401) {
      reportBackgroundRefreshError(error);
      return;
    }
    if (error.status === 401) clearBackgroundRefreshError();
    credentialList.replaceChildren(text("p", error.message, "error"));""",
            script,
        )

    def test_api_rejects_non_finite_and_giant_thresholds(self) -> None:
        token = "test-token-that-is-long-enough-123456"
        server = create_server(self.store, token, 0)
        session = authorize(server)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            for threshold in (float("nan"), 10**400):
                body = json.dumps(
                    {
                        "provider": "Example",
                        "name": "Primary",
                        "api_key": "secret",
                        "threshold": threshold,
                    }
                ).encode()
                request = urllib.request.Request(
                    f"{base}/api/credentials",
                    data=body,
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"KeyGuard-Session {session}",
                    },
                )
                with self.assertRaises(urllib.error.HTTPError) as rejected:
                    urllib.request.urlopen(request)
                self.assertEqual(422, rejected.exception.code)
                rejected.exception.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_api_persists_validated_per_credential_polling_config(self) -> None:
        token = "test-token-that-is-long-enough-123456"
        server = create_server(self.store, token, 0)
        session = authorize(server)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            body = {
                "provider": "openrouter",
                "name": "Custom schedule",
                "api_key": "management-secret",
                "threshold": 20,
                "metadata": {"key_hash": "a" * 64},
                "protection_action": "disable",
                "notifications_muted": True,
                "polling": {
                    "quiet_interval_seconds": 7200,
                    "watch_interval_seconds": 1800,
                    "safety_margin_seconds": 321,
                    "jitter_fraction": 0.1,
                },
            }
            request = urllib.request.Request(
                f"{base}/api/credentials",
                data=json.dumps(body).encode(),
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"KeyGuard-Session {session}",
                },
            )
            with urllib.request.urlopen(request) as response:
                created = json.loads(response.read())["credential"]
            self.assertEqual(7200, created["polling_config"]["quiet_interval_seconds"])
            self.assertEqual(1800, created["polling_config"]["watch_interval_seconds"])
            self.assertEqual(321, created["polling_config"]["safety_margin_seconds"])
            self.assertEqual(0.1, created["polling_config"]["jitter_fraction"])
            self.assertEqual("due", created["scheduler"]["polling_tier"])
            self.assertTrue(created["notifications_muted"])

            patch_request = urllib.request.Request(
                f"{base}/api/credentials/{created['id']}",
                data=json.dumps(
                    {
                        "notifications_muted": False,
                        "polling": {"quiet_interval_seconds": 6000},
                    }
                ).encode(),
                method="PATCH",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"KeyGuard-Session {session}",
                },
            )
            with urllib.request.urlopen(patch_request) as response:
                updated = json.loads(response.read())["credential"]
            self.assertEqual(6000, updated["polling_config"]["quiet_interval_seconds"])
            self.assertEqual(321, updated["polling_config"]["safety_margin_seconds"])
            self.assertEqual(0.1, updated["polling_config"]["jitter_fraction"])
            self.assertFalse(updated["notifications_muted"])

            for index in range(15):
                self.store.record_event(created["id"], "test_event", str(index))
            for index in range(15):
                minute = {13: 14, 14: 13}.get(index, index)
                self.store.record_usage_snapshot(
                    created["id"],
                    {
                        "checked_at": f"2026-10-17T10:{minute:02d}:00+00:00",
                        "used": index,
                        "limit": 20,
                        "remaining": 20 - index,
                        "unit": "USD",
                        "provider_status": {},
                    },
                )
            history_request = urllib.request.Request(
                f"{base}/api/credentials/{created['id']}/history?limit=12",
                headers={"Authorization": f"KeyGuard-Session {session}"},
            )
            with urllib.request.urlopen(history_request) as response:
                history_payload = json.loads(response.read())
                events = history_payload["events"]
                usage = history_payload["usage"]
            self.assertEqual(12, len(events))
            self.assertEqual("14", events[0]["result"])
            self.assertEqual(12, len(usage))
            self.assertEqual({"checked_at", "used", "unit"}, set(usage[0]))
            self.assertEqual(3, usage[0]["used"])
            self.assertEqual([14, 13], [item["used"] for item in usage[-2:]])
            self.assertEqual(
                sorted(item["checked_at"] for item in usage),
                [item["checked_at"] for item in usage],
            )

            for index in range(15, 115):
                self.store.record_usage_snapshot(
                    created["id"],
                    {
                        "checked_at": (
                            f"2026-10-18T{11 + (index - 15) // 60:02d}:"
                            f"{(index - 15) % 60:02d}:00+00:00"
                        ),
                        "used": index,
                        "limit": 120,
                        "remaining": 120 - index,
                        "unit": "USD",
                        "provider_status": {},
                    },
                )
            unbounded_request = urllib.request.Request(
                f"{base}/api/credentials/{created['id']}/history",
                headers={"Authorization": f"KeyGuard-Session {session}"},
            )
            with urllib.request.urlopen(unbounded_request) as response:
                unbounded_payload = json.loads(response.read())
            self.assertEqual(
                len(self.store.history(created["id"])),
                len(unbounded_payload["events"]),
            )
            self.assertEqual(100, len(unbounded_payload["usage"]))
            self.assertEqual(15, unbounded_payload["usage"][0]["used"])
            self.assertEqual(114, unbounded_payload["usage"][-1]["used"])

            invalid_limit = urllib.request.Request(
                f"{base}/api/credentials/{created['id']}/history?limit=0",
                headers={"Authorization": f"KeyGuard-Session {session}"},
            )
            with self.assertRaises(urllib.error.HTTPError) as context:
                urllib.request.urlopen(invalid_limit)
            self.assertEqual(422, context.exception.code)
            context.exception.close()

            body["polling"] = {"quiet_distance": 5, "watch_distance": 10}
            rejected = urllib.request.Request(
                f"{base}/api/credentials",
                data=json.dumps(body).encode(),
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"KeyGuard-Session {session}",
                },
            )
            with self.assertRaises(urllib.error.HTTPError) as context:
                urllib.request.urlopen(rejected)
            self.assertEqual(422, context.exception.code)
            context.exception.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_api_notification_mute_only_update_keeps_existing_schedule(self) -> None:
        token = "test-token-that-is-long-enough-123456"
        server = create_server(self.store, token, 0)
        session = authorize(server)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            create_request = urllib.request.Request(
                f"{base}/api/credentials",
                data=json.dumps(
                    {
                        "provider": "Example",
                        "name": "Muted without rescheduling",
                        "api_key": "secret",
                        "threshold": 10,
                    }
                ).encode(),
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"KeyGuard-Session {session}",
                },
            )
            with urllib.request.urlopen(create_request) as response:
                created = json.loads(response.read())["credential"]

            with patch.object(server.scheduler, "schedule_now") as schedule_now:
                mute_request = urllib.request.Request(
                    f"{base}/api/credentials/{created['id']}",
                    data=json.dumps({"notifications_muted": True}).encode(),
                    method="PATCH",
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"KeyGuard-Session {session}",
                    },
                )
                with urllib.request.urlopen(mute_request) as response:
                    updated = json.loads(response.read())["credential"]

            self.assertTrue(updated["notifications_muted"])
            schedule_now.assert_not_called()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_api_settings_form_mute_only_update_keeps_existing_schedule(self) -> None:
        token = "test-token-that-is-long-enough-123456"
        server = create_server(self.store, token, 0)
        session = authorize(server)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            create_request = urllib.request.Request(
                f"{base}/api/credentials",
                data=json.dumps(
                    {
                        "provider": "Example",
                        "name": "Muted from settings",
                        "api_key": "secret",
                        "threshold": 10,
                    }
                ).encode(),
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"KeyGuard-Session {session}",
                },
            )
            with urllib.request.urlopen(create_request) as response:
                created = json.loads(response.read())["credential"]

            with sqlite3.connect(self.path) as database:
                database.execute(
                    "UPDATE credentials SET polling_config_json = '{}' WHERE id = ?",
                    (created["id"],),
                )

            with patch.object(server.scheduler, "schedule_now") as schedule_now:
                mute_request = urllib.request.Request(
                    f"{base}/api/credentials/{created['id']}",
                    data=json.dumps(
                        {
                            "threshold": created["threshold"],
                            "auto_protect": created["auto_protect"],
                            "notifications_muted": True,
                            "protection_action": created["protection_action"],
                            "polling": created["polling_config"],
                        }
                    ).encode(),
                    method="PATCH",
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"KeyGuard-Session {session}",
                    },
                )
                with urllib.request.urlopen(mute_request) as response:
                    updated = json.loads(response.read())["credential"]

            self.assertTrue(updated["notifications_muted"])
            schedule_now.assert_not_called()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_vault_and_database_update_are_serialized(self) -> None:
        self.store.close()
        vault = BlockingVault()
        self.store = Store(self.path, vault)
        created = self.store.create_credential(
            provider="Example",
            name="Primary",
            secret="old-secret",
            threshold=None,
            auto_protect=False,
        )
        vault.block = True
        update = threading.Thread(
            target=self.store.update_credential,
            args=(created["id"], {"api_key": "new-secret", "name": "Updated"}),
        )
        update.start()
        self.assertTrue(vault.entered.wait(timeout=1))
        read_finished = threading.Event()
        read = threading.Thread(
            target=lambda: (self.store.list_credentials(), read_finished.set())
        )
        read.start()
        self.assertFalse(read_finished.wait(timeout=0.05))
        vault.release.set()
        update.join(timeout=2)
        read.join(timeout=2)
        self.assertTrue(read_finished.is_set())
        self.assertEqual("Updated", self.store.get_credential(created["id"])["name"])

    def test_failed_create_cleanup_keeps_orphan_discoverable(self) -> None:
        self.store.close()
        vault = CleanupFailVault()
        self.store = Store(self.path, vault)
        with (
            patch.object(
                self.store,
                "_record_event_locked",
                side_effect=RuntimeError("event write failed"),
            ),
            self.assertRaisesRegex(RuntimeError, "cleanup remains tracked"),
        ):
            self.store.create_credential(
                provider="Example",
                name="Primary",
                secret="secret",
                threshold=None,
                auto_protect=False,
            )
        records = self.store.list_credentials()
        self.assertEqual(1, len(records))
        self.assertEqual("cleanup_required", records[0]["status"])
        self.assertIn(records[0]["id"], vault.secrets)

    def test_installer_generates_user_service_and_desktop_launcher(self) -> None:
        service_dir = Path(self.temp.name) / "systemd" / "user"
        app_dir = Path(self.temp.name) / "applications"
        with (
            patch.object(cli, "systemd_user_dir", return_value=service_dir),
            patch.object(cli, "applications_dir", return_value=app_dir),
            patch.object(
                cli, "auth_token_path", return_value=Path(self.temp.name) / "token"
            ),
            patch.object(cli, "_systemctl", return_value="/usr/bin/systemctl"),
            patch.object(cli.subprocess, "run") as run,
        ):
            cli.install()

        service = (service_dir / "keyguard.service").read_text()
        desktop = (app_dir / "dev.tanner.KeyGuard.desktop").read_text()
        self.assertIn("Type=simple", service)
        self.assertIn("Restart=on-failure", service)
        self.assertIn("-m keyguard.cli serve", service)
        self.assertIn("-m keyguard.cli open", desktop)
        self.assertEqual(
            [
                ((["/usr/bin/systemctl", "--user", "daemon-reload"],), {"check": True}),
                (
                    (
                        [
                            "/usr/bin/systemctl",
                            "--user",
                            "enable",
                            "keyguard.service",
                        ],
                    ),
                    {"check": True},
                ),
                (
                    (
                        [
                            "/usr/bin/systemctl",
                            "--user",
                            "restart",
                            "keyguard.service",
                        ],
                    ),
                    {"check": True},
                ),
            ],
            [(call.args, call.kwargs) for call in run.call_args_list],
        )

    def test_exec_path_quoting_handles_spaces_and_reserved_markers(self) -> None:
        path = "/home/user/Key Guard%$venv/bin/python"
        self.assertEqual(
            '"/home/user/Key Guard%%$$venv/bin/python"', cli._systemd_quote(path)
        )
        self.assertEqual(
            '"/home/user/Key Guard%%\\$venv/bin/python"', cli._desktop_quote(path)
        )

    def test_launcher_starts_or_reuses_daemon_then_opens_dashboard(self) -> None:
        with (
            patch.object(cli, "_systemctl", return_value="/usr/bin/systemctl"),
            patch.object(
                cli, "auth_token_path", return_value=Path(self.temp.name) / "token"
            ),
            patch.object(cli.subprocess, "run") as run,
            patch.object(cli, "_wait_for_daemon", return_value=24567) as wait,
            patch.object(
                cli,
                "mint_bootstrap",
                return_value="one-time-bootstrap-token-1234567890",
            ),
            patch.object(cli.webbrowser, "open") as open_browser,
        ):
            cli.open_dashboard()

        run.assert_called_once_with(
            ["/usr/bin/systemctl", "--user", "start", "keyguard.service"],
            check=True,
        )
        token = (Path(self.temp.name) / "token").read_text().strip()
        wait.assert_called_once_with(token)
        open_browser.assert_called_once_with(
            "http://127.0.0.1:24567/#token=one-time-bootstrap-token-1234567890",
            new=2,
        )

    def test_runtime_port_is_owner_only_and_not_host_wide_fixed(self) -> None:
        port_path = Path(self.temp.name) / "daemon-port"
        with patch.object(cli, "runtime_port_path", return_value=port_path):
            self.assertIsNone(cli._read_port())
            cli._write_port(24567)
            self.assertEqual(24567, cli._read_port())
        self.assertEqual(0o600, port_path.stat().st_mode & 0o777)

    def test_runtime_port_cleanup_removes_only_the_stopping_daemon_record(
        self,
    ) -> None:
        port_path = Path(self.temp.name) / "daemon-port"
        with patch.object(cli, "runtime_port_path", return_value=port_path):
            cli._write_port(24567)
            cli._clear_port(24567)
            self.assertFalse(port_path.exists())

            cli._write_port(24568)
            cli._clear_port(24567)
            self.assertEqual(24568, cli._read_port())

    def test_delete_removes_secret_and_database_record(self) -> None:
        created = self.store.create_credential(
            provider="Example",
            name="Primary",
            secret="secret",
            threshold=None,
            auto_protect=False,
        )
        self.assertTrue(self.store.delete_credential(created["id"]))
        self.assertNotIn(created["id"], self.vault.secrets)
        self.assertIsNone(self.store.get_credential(created["id"]))


if __name__ == "__main__":
    unittest.main()
