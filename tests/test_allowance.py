from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import Mock

from keyguard.api import ApiError, _metadata, create_server
from keyguard.auth import mint_bootstrap
from keyguard.notifications import NotificationError
from keyguard.providers import ProviderRegistry
from keyguard.providers.base import BalanceSnapshot, ProviderError
from keyguard.store import Store

OWNER_TOKEN = "test-token-that-is-long-enough-123456"


class FakeVault:
    def __init__(self) -> None:
        self.secrets: dict[str, str] = {}

    def set(self, credential_id: str, secret: str) -> None:
        self.secrets[credential_id] = secret

    def get(self, credential_id: str) -> str | None:
        return self.secrets.get(credential_id)

    def delete(self, credential_id: str) -> None:
        self.secrets.pop(credential_id, None)


class AllowanceAdapter:
    provider_id = "allowance-test"
    capabilities = frozenset({"CAN_FETCH_USAGE", "CAN_FETCH_BALANCE"})
    actions: tuple[str, ...] = ()

    def __init__(self) -> None:
        self.available: float | None = 20.0
        self.unit = "USD"
        self.error: ProviderError | None = None
        self.calls: list[tuple[str, dict[str, object]]] = []

    def validate_metadata(self, metadata: dict[str, object]) -> dict[str, object]:
        return dict(metadata)

    def fetch_balance(
        self, secret: str, metadata: dict[str, object]
    ) -> BalanceSnapshot:
        self.calls.append((secret, dict(metadata)))
        if self.error is not None:
            raise self.error
        return BalanceSnapshot(available=self.available, unit=self.unit)

    def execute_action(
        self, action: str, secret: str, metadata: dict[str, object]
    ) -> dict[str, object]:
        raise AssertionError(
            "allowance verification must not execute a provider action"
        )


class AllowanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state.db"
        self.vault = FakeVault()
        self.store = Store(self.path, self.vault)
        self.adapter = AllowanceAdapter()
        self.server = create_server(
            self.store,
            OWNER_TOKEN,
            0,
            providers=ProviderRegistry([self.adapter]),
        )
        bootstrap = mint_bootstrap(OWNER_TOKEN)
        self.session = self.server.authority.exchange_bootstrap(bootstrap)
        assert self.session is not None
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.store.close()
        self.temp.cleanup()

    def request(
        self, method: str, path: str, payload: dict[str, object]
    ) -> tuple[int, dict[str, object]]:
        request = urllib.request.Request(
            self.base + path,
            data=json.dumps(payload).encode(),
            method=method,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"KeyGuard-Session {self.session}",
            },
        )
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            try:
                return error.code, json.loads(error.read())
            finally:
                error.close()

    def create_payload(self, **updates: object) -> dict[str, object]:
        payload: dict[str, object] = {
            "provider": self.adapter.provider_id,
            "name": "Allowance credential",
            "api_key": "management-secret",
            "metadata": {"scope": "one-key"},
            "protection_action": "notify_only",
        }
        payload.update(updates)
        return payload

    def test_verified_allowance_is_persisted_and_omission_is_compatible(self) -> None:
        status, payload = self.request(
            "POST",
            "/api/credentials",
            self.create_payload(starting_allowance=20),
        )

        self.assertEqual(201, status)
        credential = payload["credential"]
        self.assertEqual(20.0, credential["starting_allowance"])
        self.assertEqual("USD", credential["starting_allowance_unit"])
        self.assertEqual(
            [("management-secret", {"scope": "one-key"})], self.adapter.calls
        )
        persisted = self.store.get_credential(credential["id"])
        self.assertEqual(20.0, persisted["starting_allowance"])
        self.assertEqual("USD", persisted["starting_allowance_unit"])

        self.adapter.calls.clear()
        status, payload = self.request(
            "POST",
            "/api/credentials",
            self.create_payload(name="Legacy client"),
        )
        self.assertEqual(201, status)
        self.assertIsNone(payload["credential"]["starting_allowance"])
        self.assertEqual([], self.adapter.calls)

    def test_secret_named_metadata_is_rejected_before_persistence(self) -> None:
        leaked_secret = "must-never-reach-sqlite-or-dashboard"

        for field in (
            "api-key",
            "api_token",
            "refresh_token",
            "session_token",
            "openaiApiKey",
            "github_token",
            "oauth_refresh_token",
        ):
            with self.subTest(field=field):
                status, payload = self.request(
                    "POST",
                    "/api/credentials",
                    self.create_payload(
                        metadata={
                            "scope": "one-key",
                            "nested": [{field: leaked_secret}],
                        }
                    ),
                )
                self.assertEqual(422, status)
                self.assertEqual("VALIDATION_ERROR", payload["error"]["code"])
                self.assertEqual([], self.store.list_credentials())
                self.assertEqual({}, self.vault.secrets)
        self.assertEqual([], self.store.list_credentials())
        self.assertEqual({}, self.vault.secrets)
        self.assertNotIn(leaked_secret.encode(), self.path.read_bytes())

        status, payload = self.request(
            "POST", "/api/credentials", self.create_payload()
        )
        self.assertEqual(201, status)
        credential_id = payload["credential"]["id"]

        status, payload = self.request(
            "PATCH",
            f"/api/credentials/{credential_id}",
            {"metadata": {"nested": {"client_secret": leaked_secret}}},
        )

        self.assertEqual(422, status)
        self.assertEqual("VALIDATION_ERROR", payload["error"]["code"])
        persisted = self.store.get_credential(credential_id)
        self.assertEqual({"scope": "one-key"}, persisted["provider_metadata"])
        self.assertNotIn(leaked_secret.encode(), self.path.read_bytes())

    def test_non_secret_identifiers_and_hashes_remain_valid_metadata(self) -> None:
        metadata = {
            "key_hash": "sha256-value",
            "management_key_hash": "provider-fingerprint",
            "credential_id": "provider-credential-id",
            "account_id": "account-id",
        }

        status, payload = self.request(
            "POST", "/api/credentials", self.create_payload(metadata=metadata)
        )

        self.assertEqual(201, status)
        self.assertEqual(metadata, payload["credential"]["provider_metadata"])

    def test_deeply_nested_secret_metadata_is_a_validation_error(self) -> None:
        nested: object = {"api_token": "must-not-persist"}
        for _ in range(1_200):
            nested = [nested]

        with self.assertRaises(ApiError) as rejected:
            _metadata({"nested": nested})

        self.assertEqual(422, rejected.exception.status)
        self.assertEqual("VALIDATION_ERROR", rejected.exception.code)
        self.assertIn("must not contain secrets", rejected.exception.message)

    def test_excessive_create_is_rejected_not_saved_and_notified(self) -> None:
        self.store.update_notification_config({"enabled": True})
        self.server.notifications.send = Mock()

        status, payload = self.request(
            "POST",
            "/api/credentials",
            self.create_payload(starting_allowance=30),
        )

        self.assertEqual(422, status)
        self.assertEqual("ALLOWANCE_EXCEEDS_AVAILABLE_CREDIT", payload["error"]["code"])
        self.assertIn("30 USD", payload["error"]["message"])
        self.assertIn("20 USD", payload["error"]["message"])
        self.assertEqual([], self.store.list_credentials())
        self.assertEqual({}, self.vault.secrets)
        self.server.notifications.send.assert_called_once()
        self.assertEqual(
            "urgent", self.server.notifications.send.call_args.kwargs["priority"]
        )

    def test_missing_remaining_credit_rejects_without_assuming_zero(self) -> None:
        self.adapter.available = None

        status, payload = self.request(
            "POST",
            "/api/credentials",
            self.create_payload(starting_allowance=1),
        )

        self.assertEqual(422, status)
        self.assertEqual("ALLOWANCE_UNVERIFIED", payload["error"]["code"])
        self.assertIn(
            "did not report authoritative available credit", payload["error"]["message"]
        )
        self.assertEqual([], self.store.list_credentials())

    def test_invalid_provider_balance_rejects_without_saving(self) -> None:
        for available in (float("nan"), -1.0):
            with self.subTest(available=available):
                self.adapter.available = available

                status, payload = self.request(
                    "POST",
                    "/api/credentials",
                    self.create_payload(starting_allowance=0),
                )

                self.assertEqual(422, status)
                self.assertEqual("ALLOWANCE_UNVERIFIED", payload["error"]["code"])
                self.assertEqual([], self.store.list_credentials())

    def test_create_validates_complete_payload_before_provider_call(self) -> None:
        self.adapter.available = 0

        status, payload = self.request(
            "POST",
            "/api/credentials",
            self.create_payload(starting_allowance=1, polling="not-an-object"),
        )

        self.assertEqual(422, status)
        self.assertEqual("POLLING_CONFIGURATION_ERROR", payload["error"]["code"])
        self.assertEqual([], self.adapter.calls)
        self.assertEqual([], self.store.list_credentials())

    def test_provider_error_rejects_allowance_without_saving(self) -> None:
        self.adapter.error = ProviderError("authoritative provider check failed")

        status, payload = self.request(
            "POST",
            "/api/credentials",
            self.create_payload(starting_allowance=1),
        )

        self.assertEqual(502, status)
        self.assertEqual("PROVIDER_ERROR", payload["error"]["code"])
        self.assertEqual([], self.store.list_credentials())

    def test_failed_increase_preserves_allowance_and_replacement_secret(self) -> None:
        created = self.store.create_credential(
            provider=self.adapter.provider_id,
            name="Existing",
            secret="old-secret",
            threshold=None,
            auto_protect=False,
            starting_allowance=5,
            provider_metadata={"scope": "one-key"},
        )
        self.store.update_notification_config({"enabled": True})
        self.server.notifications.send = Mock()

        status, payload = self.request(
            "PATCH",
            f"/api/credentials/{created['id']}",
            {
                "starting_allowance": 30,
                "api_key": "replacement-secret",
            },
        )

        self.assertEqual(422, status)
        self.assertEqual("ALLOWANCE_EXCEEDS_AVAILABLE_CREDIT", payload["error"]["code"])
        current = self.store.get_credential(created["id"])
        self.assertEqual(5.0, current["starting_allowance"])
        self.assertEqual("old-secret", self.vault.secrets[created["id"]])
        self.assertEqual("replacement-secret", self.adapter.calls[-1][0])
        self.server.notifications.send.assert_called_once()
        events = self.store.history(created["id"])
        event = next(
            item for item in events if item["event_type"] == "allowance_validation"
        )
        self.assertEqual("rejected", event["result"])

    def test_identity_change_revalidates_unchanged_allowance_atomically(self) -> None:
        created = self.store.create_credential(
            provider=self.adapter.provider_id,
            name="Existing",
            secret="old-secret",
            threshold=None,
            auto_protect=False,
            starting_allowance=5,
            starting_allowance_unit="USD",
            provider_metadata={"scope": "one-key"},
        )
        self.adapter.available = 4

        status, payload = self.request(
            "PATCH",
            f"/api/credentials/{created['id']}",
            {
                "api_key": "replacement-secret",
                "metadata": {"scope": "another-key"},
            },
        )

        self.assertEqual(422, status)
        self.assertEqual("ALLOWANCE_EXCEEDS_AVAILABLE_CREDIT", payload["error"]["code"])
        current = self.store.get_credential(created["id"])
        self.assertEqual({"scope": "one-key"}, current["provider_metadata"])
        self.assertEqual("old-secret", self.vault.secrets[created["id"]])
        self.assertEqual(
            ("replacement-secret", {"scope": "another-key"}),
            self.adapter.calls[-1],
        )

    def test_failed_patch_uses_persisted_mute_state_and_records_history(self) -> None:
        created = self.store.create_credential(
            provider=self.adapter.provider_id,
            name="Existing",
            secret="secret",
            threshold=None,
            auto_protect=False,
            starting_allowance=5,
            starting_allowance_unit="USD",
            notifications_muted=False,
        )
        self.store.update_notification_config({"enabled": True})
        self.server.notifications.send = Mock()

        status, _ = self.request(
            "PATCH",
            f"/api/credentials/{created['id']}",
            {"starting_allowance": 30, "notifications_muted": True},
        )

        self.assertEqual(422, status)
        self.server.notifications.send.assert_called_once()
        current = self.store.get_credential(created["id"])
        self.assertFalse(current["notifications_muted"])
        self.assertEqual(
            "rejected",
            next(
                event
                for event in self.store.history(created["id"])
                if event["event_type"] == "allowance_validation"
            )["result"],
        )

    def test_muted_rejection_still_records_source_event(self) -> None:
        created = self.store.create_credential(
            provider=self.adapter.provider_id,
            name="Muted",
            secret="secret",
            threshold=None,
            auto_protect=False,
            starting_allowance=5,
            starting_allowance_unit="USD",
            notifications_muted=True,
        )
        self.store.update_notification_config({"enabled": True})
        self.server.notifications.send = Mock()

        status, _ = self.request(
            "PATCH",
            f"/api/credentials/{created['id']}",
            {"starting_allowance": 30, "notifications_muted": False},
        )

        self.assertEqual(422, status)
        self.server.notifications.send.assert_not_called()
        events = self.store.history(created["id"])
        self.assertTrue(
            any(event["event_type"] == "allowance_validation" for event in events)
        )

    def test_missing_stored_secret_maps_to_provider_error(self) -> None:
        created = self.store.create_credential(
            provider=self.adapter.provider_id,
            name="Missing secret",
            secret="secret",
            threshold=None,
            auto_protect=False,
            starting_allowance=5,
            starting_allowance_unit="USD",
        )
        self.vault.delete(created["id"])

        status, payload = self.request(
            "PATCH",
            f"/api/credentials/{created['id']}",
            {"starting_allowance": 6},
        )

        self.assertEqual(502, status)
        self.assertEqual("PROVIDER_ERROR", payload["error"]["code"])
        self.assertEqual(5.0, self.store.get_credential(created["id"])["starting_allowance"])

    def test_notification_failure_does_not_hide_allowance_rejection(self) -> None:
        self.store.update_notification_config({"enabled": True})
        self.server.notifications.send = Mock(
            side_effect=NotificationError("ntfy unavailable")
        )

        status, payload = self.request(
            "POST",
            "/api/credentials",
            self.create_payload(starting_allowance=30),
        )

        self.assertEqual(422, status)
        self.assertEqual("ALLOWANCE_EXCEEDS_AVAILABLE_CREDIT", payload["error"]["code"])
        self.assertEqual([], self.store.list_credentials())

    def test_existing_database_migrates_and_allowance_survives_restart(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.store.close()
        database = sqlite3.connect(self.path)
        try:
            database.execute("ALTER TABLE credentials DROP COLUMN starting_allowance")
            database.execute(
                "ALTER TABLE credentials DROP COLUMN starting_allowance_unit"
            )
            database.commit()
        finally:
            database.close()
        self.store = Store(self.path, self.vault)
        columns = {
            row[1]
            for row in self.store._db.execute(
                "PRAGMA table_info(credentials)"
            ).fetchall()
        }
        self.assertIn("starting_allowance", columns)
        self.assertIn("starting_allowance_unit", columns)
        created = self.store.create_credential(
            provider=self.adapter.provider_id,
            name="Persisted",
            secret="secret",
            threshold=None,
            auto_protect=False,
            starting_allowance=7.5,
            starting_allowance_unit="USD",
        )
        self.store.close()
        self.store = Store(self.path, self.vault)
        self.assertEqual(
            7.5,
            self.store.get_credential(created["id"])["starting_allowance"],
        )
        self.assertEqual(
            "USD",
            self.store.get_credential(created["id"])["starting_allowance_unit"],
        )
        self.server = create_server(
            self.store,
            OWNER_TOKEN,
            0,
            providers=ProviderRegistry([self.adapter]),
        )
        bootstrap = mint_bootstrap(OWNER_TOKEN)
        self.session = self.server.authority.exchange_bootstrap(bootstrap)
        assert self.session is not None
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def test_dashboard_exposes_allowance_in_create_edit_and_card_views(self) -> None:
        root = Path(__file__).parents[1] / "src" / "keyguard" / "dashboard"
        html = (root / "index.html").read_text()
        script = (root / "app.js").read_text()

        self.assertIn('name="starting_allowance"', html)
        self.assertIn('allowance.name = "starting_allowance"', script)
        self.assertIn(
            'number(credential.starting_allowance, credential.starting_allowance_unit)',
            script,
        )
        self.assertIn("starting_allowance: startingAllowance", script)


if __name__ == "__main__":
    unittest.main()
