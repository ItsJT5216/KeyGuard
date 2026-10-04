from __future__ import annotations

import json
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
from keyguard.auth import load_or_create_token
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

    def test_api_never_returns_raw_secret_and_rejects_remote_origin(self) -> None:
        token = "test-token-that-is-long-enough-123456"
        server = create_server(self.store, token, 0)
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
                    "Authorization": f"Bearer {token}",
                },
            )
            with urllib.request.urlopen(request) as response:
                created_payload = response.read()
            self.assertNotIn(secret.encode(), created_payload)

            listing = urllib.request.Request(
                f"{base}/api/credentials",
                headers={"Authorization": f"Bearer {token}"},
            )
            with urllib.request.urlopen(listing) as response:
                list_payload = response.read()
            self.assertNotIn(secret.encode(), list_payload)
            self.assertNotIn(b"api_key", list_payload)

            rejected = urllib.request.Request(
                f"{base}/api/credentials",
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Origin": "https://attacker.example",
                    "Authorization": f"Bearer {token}",
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
        token = load_or_create_token(path)
        self.assertEqual(token, load_or_create_token(path))
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        self.assertEqual(0o700, path.parent.stat().st_mode & 0o777)

    def test_api_requires_auth_validates_host_and_uses_http_only_session(self) -> None:
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

            bad_host = urllib.request.Request(
                f"{base}/api/status",
                headers={"Authorization": f"Bearer {token}", "Host": "evil.example"},
            )
            with self.assertRaises(urllib.error.HTTPError) as rejected:
                urllib.request.urlopen(bad_host)
            self.assertEqual(421, rejected.exception.code)
            rejected.exception.close()

            session = urllib.request.Request(
                f"{base}/api/session",
                data=b"",
                method="POST",
                headers={"Authorization": f"Bearer {token}"},
            )
            with urllib.request.urlopen(session) as response:
                cookie = response.headers["Set-Cookie"]
            self.assertIn("HttpOnly", cookie)
            self.assertIn("SameSite=Strict", cookie)

            status = urllib.request.Request(
                f"{base}/api/status", headers={"Cookie": cookie.split(";", 1)[0]}
            )
            with urllib.request.urlopen(status) as response:
                self.assertEqual(200, response.status)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_api_rejects_non_finite_and_giant_thresholds(self) -> None:
        token = "test-token-that-is-long-enough-123456"
        server = create_server(self.store, token, 0)
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
                        "Authorization": f"Bearer {token}",
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
            patch.object(cli, "_port", return_value=17832),
            patch.object(cli, "_systemctl", return_value="/usr/bin/systemctl"),
            patch.object(
                cli, "auth_token_path", return_value=Path(self.temp.name) / "token"
            ),
            patch.object(cli.subprocess, "run") as run,
            patch.object(cli, "_wait_for_daemon") as wait,
            patch.object(cli.webbrowser, "open") as open_browser,
        ):
            cli.open_dashboard()

        run.assert_called_once_with(
            ["/usr/bin/systemctl", "--user", "start", "keyguard.service"],
            check=True,
        )
        token = (Path(self.temp.name) / "token").read_text().strip()
        wait.assert_called_once_with(17832, token)
        open_browser.assert_called_once_with(
            f"http://127.0.0.1:17832/#token={token}", new=2
        )

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
