from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock, patch

from keyguard import cli
from keyguard.api import create_server
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
        server = create_server(self.store, 0)
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
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request) as response:
                created_payload = response.read()
            self.assertNotIn(secret.encode(), created_payload)

            with urllib.request.urlopen(f"{base}/api/credentials") as response:
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
        vault = KeyringVault()
        backend = MagicMock()
        vault._keyring = backend

        vault.set("credential-id", "raw-value")
        backend.set_password.assert_called_once_with(
            SERVICE_NAME, "credential:credential-id", "raw-value"
        )

    def test_installer_generates_user_service_and_desktop_launcher(self) -> None:
        service_dir = Path(self.temp.name) / "systemd" / "user"
        app_dir = Path(self.temp.name) / "applications"
        with (
            patch.object(cli, "systemd_user_dir", return_value=service_dir),
            patch.object(cli, "applications_dir", return_value=app_dir),
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
                            "--now",
                            "keyguard.service",
                        ],
                    ),
                    {"check": True},
                ),
            ],
            [(call.args, call.kwargs) for call in run.call_args_list],
        )

    def test_launcher_starts_or_reuses_daemon_then_opens_dashboard(self) -> None:
        with (
            patch.object(cli, "_port", return_value=17832),
            patch.object(cli, "_systemctl", return_value="/usr/bin/systemctl"),
            patch.object(cli.subprocess, "run") as run,
            patch.object(cli, "_wait_for_daemon") as wait,
            patch.object(cli.webbrowser, "open") as open_browser,
        ):
            cli.open_dashboard()

        run.assert_called_once_with(
            ["/usr/bin/systemctl", "--user", "start", "keyguard.service"],
            check=True,
        )
        wait.assert_called_once_with(17832)
        open_browser.assert_called_once_with("http://127.0.0.1:17832/", new=2)

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
