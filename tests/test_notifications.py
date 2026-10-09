from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from keyguard.api import create_server
from keyguard.auth import mint_bootstrap
from keyguard.notifications import NtfyNotifier, NotificationError
from keyguard.scheduler import AdaptiveScheduler
from keyguard.store import Store


class FakeVault:
    def __init__(self) -> None:
        self.secrets: dict[str, str] = {}

    def set(self, credential_id: str, secret: str) -> None:
        self.secrets[credential_id] = secret

    def get(self, credential_id: str) -> str | None:
        return self.secrets.get(credential_id)

    def delete(self, credential_id: str) -> None:
        self.secrets.pop(credential_id, None)


class Response:
    status = 200

    def close(self) -> None:
        pass


class FakeProtection:
    @contextmanager
    def credential_operation(self, _credential_id: str):
        yield


class NotificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.vault = FakeVault()
        self.store = Store(Path(self.temp.name) / "state.db", self.vault)
        self.credential = self.store.create_credential(
            provider="example",
            name="Freebie",
            secret="provider-secret",
            threshold=20,
            auto_protect=True,
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def configure(self) -> None:
        self.store.update_notification_config(
            {
                "server_url": "https://ntfy.example",
                "topic": "keyguard-home",
                "enabled": True,
                "auth_token": "ntfy-secret",
            }
        )

    def test_configuration_keeps_auth_secret_out_of_sqlite_and_api_shape(self) -> None:
        self.configure()
        config = self.store.get_notification_config()

        self.assertTrue(config["auth_configured"])
        self.assertNotIn("auth_token", config)
        self.assertEqual("ntfy-secret", self.vault.get("__notification_ntfy_auth__"))
        raw = Path(self.temp.name, "state.db").read_bytes()
        self.assertNotIn(b"ntfy-secret", raw)

    def test_notifier_uses_config_and_keyring_token(self) -> None:
        self.configure()
        requests: list[Any] = []

        def send(request: urllib.request.Request, timeout: float) -> Response:
            requests.append((request, timeout))
            return Response()

        NtfyNotifier(self.store, sender=send).test()

        request, timeout = requests[0]
        self.assertEqual("https://ntfy.example/keyguard-home", request.full_url)
        self.assertEqual("Bearer ntfy-secret", request.get_header("Authorization"))
        self.assertEqual(10.0, timeout)

    def test_event_survives_failed_delivery_and_failure_is_also_recorded(self) -> None:
        self.configure()

        def fail(_request: urllib.request.Request, _timeout: float) -> Response:
            raise urllib.error.URLError("offline")

        notifier = NtfyNotifier(self.store, sender=fail)
        event = self.store.record_event(
            self.credential["id"], "protection_action", "success", {}
        )

        delivered = notifier.deliver_event(
            self.credential,
            event,
            "protected",
            priority="high",
            tags="shield",
        )

        self.assertFalse(delivered)
        history = self.store.history(self.credential["id"])
        self.assertEqual("notification_delivery", history[0]["event_type"])
        self.assertEqual("failed", history[0]["result"])
        self.assertEqual("protection_action", history[1]["event_type"])

    def test_keyring_failure_cannot_erase_or_interrupt_the_source_event(self) -> None:
        self.configure()
        event = self.store.record_event(
            self.credential["id"], "protection_action", "success", {}
        )

        class UnavailableVault(FakeVault):
            def get(self, credential_id: str) -> str | None:
                raise RuntimeError("Secret Service unavailable")

        self.store.vault = UnavailableVault()
        notifier = NtfyNotifier(self.store, sender=lambda *_args: Response())
        delivered = notifier.deliver_event(
            self.credential, event, "protected", priority="high", tags="shield"
        )

        self.assertFalse(delivered)
        history = self.store.history(self.credential["id"])
        self.assertEqual("notification_delivery", history[0]["event_type"])
        self.assertEqual("protection_action", history[1]["event_type"])

    def test_disabled_notifications_do_not_attempt_or_record_delivery(self) -> None:
        attempts: list[str] = []

        def send(request: urllib.request.Request, _timeout: float) -> Response:
            attempts.append(request.full_url)
            return Response()

        event = self.store.record_event(
            self.credential["id"], "polling_tier_changed", "accelerated", {}
        )
        delivered = NtfyNotifier(self.store, sender=send).deliver_event(
            self.credential,
            event,
            "warning",
            priority="default",
            tags="warning",
        )

        self.assertFalse(delivered)
        self.assertEqual([], attempts)
        self.assertNotIn(
            "notification_delivery",
            [item["event_type"] for item in self.store.history(self.credential["id"])],
        )

    def test_tier_transition_notifies_once_until_tier_changes(self) -> None:
        self.configure()
        sent: list[str] = []

        def send(request: urllib.request.Request, _timeout: float) -> Response:
            sent.append(request.data.decode())
            return Response()

        notifier = NtfyNotifier(self.store, sender=send)
        scheduler = AdaptiveScheduler(
            self.store,
            FakeProtection(),
            jitter=lambda _low, _high: 0,
            notifications=notifier,
        )
        snapshot = {
            "checked_at": datetime(2026, 10, 9, tzinfo=UTC).isoformat(),
            "used": 16,
            "limit": 20,
            "remaining": 4,
            "unit": "USD",
            "provider_status": {},
        }
        self.store.record_usage_snapshot(self.credential["id"], snapshot)

        scheduler.schedule_snapshot(self.credential["id"], snapshot)
        scheduler.schedule_snapshot(self.credential["id"], snapshot)

        self.assertEqual(1, len(sent))
        events = [
            event
            for event in self.store.history(self.credential["id"])
            if event["event_type"] == "polling_tier_changed"
        ]
        self.assertEqual(1, len(events))

    def test_repeated_failure_warns_on_third_failure_only(self) -> None:
        self.configure()
        sent: list[str] = []

        def send(request: urllib.request.Request, _timeout: float) -> Response:
            sent.append(request.data.decode())
            return Response()

        scheduler = AdaptiveScheduler(
            self.store,
            FakeProtection(),
            notifications=NtfyNotifier(self.store, sender=send),
        )
        now = datetime(2026, 10, 9, tzinfo=UTC)
        for _ in range(5):
            scheduler._schedule_failure(self.credential["id"], now)

        self.assertEqual(1, len(sent))
        self.assertIn("three provider checks", sent[0])

    def test_dashboard_can_save_config_and_send_test(self) -> None:
        server = create_server(self.store, "test-token-that-is-long-enough-123456", 0)
        sent: list[str] = []

        def send(request: urllib.request.Request, _timeout: float) -> Response:
            sent.append(request.data.decode())
            return Response()

        server.notifications._sender = send
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            bootstrap = urllib.request.Request(
                f"{base}/api/session",
                data=b"",
                method="POST",
                headers={
                    "Authorization": "KeyGuard-Bootstrap "
                    + mint_bootstrap("test-token-that-is-long-enough-123456")
                },
            )
            with urllib.request.urlopen(bootstrap) as response:
                session = json.loads(response.read())["session_token"]
            headers = {
                "Authorization": f"KeyGuard-Session {session}",
                "Content-Type": "application/json",
            }
            save = urllib.request.Request(
                f"{base}/api/notifications",
                data=json.dumps(
                    {
                        "server_url": "https://ntfy.example",
                        "topic": "home",
                        "enabled": True,
                    }
                ).encode(),
                method="PATCH",
                headers=headers,
            )
            with urllib.request.urlopen(save) as response:
                config = json.loads(response.read())["notifications"]
            self.assertTrue(config["enabled"])
            test = urllib.request.Request(
                f"{base}/api/notifications/test",
                data=b"{}",
                method="POST",
                headers=headers,
            )
            with urllib.request.urlopen(test) as response:
                self.assertTrue(json.loads(response.read())["sent"])
            self.assertEqual(["KeyGuard notifications are connected."], sent)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
