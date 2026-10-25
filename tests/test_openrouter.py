from __future__ import annotations

import tempfile
import threading
import unittest
import urllib.error
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import patch

from keyguard.notifications import NtfyNotifier
from keyguard.protection import ProtectionService
from keyguard.providers import ProviderRegistry
from keyguard.providers import openrouter as openrouter_module
from keyguard.providers.base import (
    CAN_DISABLE_KEY,
    CAN_FETCH_BALANCE,
    CAN_FETCH_USAGE,
    CAN_IDENTIFY_INDIVIDUAL_KEY_USAGE,
    ProviderError,
)
from keyguard.providers.openrouter import OpenRouterAdapter, OpenRouterTransport
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


class CapturingNotifications:
    def __init__(self, store: Store | None = None) -> None:
        self.deliveries: list[dict[str, Any]] = []
        self.store = store

    def deliver_event(
        self,
        credential: dict[str, Any],
        event: dict[str, Any] | None,
        message: str,
        *,
        priority: str,
        tags: str,
    ) -> bool:
        self.deliveries.append(
            {
                "credential": credential,
                "event": event,
                "message": message,
                "priority": priority,
                "tags": tags,
            }
        )
        if self.store is not None and event is not None:
            self.store.record_event(
                credential["id"],
                "notification_delivery",
                "success",
                {"source_event_id": event["id"]},
            )
        return True


class RecordedTransport:
    def __init__(self, responses: list[dict[str, Any] | Exception]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, str, dict[str, Any] | None]] = []

    def request(
        self,
        method: str,
        path: str,
        token: str,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.calls.append((method, path, token, body))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class BlockingTransport(RecordedTransport):
    def __init__(self, responses: list[dict[str, Any] | Exception]) -> None:
        super().__init__(responses)
        self.first_call_started = threading.Event()
        self.release_first_call = threading.Event()

    def request(
        self,
        method: str,
        path: str,
        token: str,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not self.calls:
            self.first_call_started.set()
            self.release_first_call.wait(timeout=2)
        return super().request(method, path, token, body)


def key_payload(
    *,
    usage: float,
    disabled: bool = False,
    limit: float = 20.0,
    limit_reset: str | None = None,
    expires_at: str | None = None,
) -> dict[str, Any]:
    return {
        "data": {
            "hash": "a" * 64,
            "usage": usage,
            "limit": limit,
            "limit_remaining": max(limit - usage, 0),
            "limit_reset": limit_reset,
            "expires_at": expires_at,
            "disabled": disabled,
        }
    }


class OpenRouterAdapterTests(unittest.TestCase):
    def test_fetches_authoritative_account_credit_balance(self) -> None:
        transport = RecordedTransport(
            [{"data": {"total_credits": 100.5, "total_usage": 25.75}}]
        )
        adapter = OpenRouterAdapter(transport)

        balance = adapter.fetch_balance(
            "management-secret", {"key_hash": "a" * 64}
        )

        self.assertIn(CAN_FETCH_BALANCE, adapter.capabilities)
        self.assertEqual(74.75, balance.available)
        self.assertEqual("USD", balance.unit)
        self.assertEqual(
            [("GET", "/credits", "management-secret", None)], transport.calls
        )

    def test_malformed_credit_balance_is_rejected(self) -> None:
        for payload in (
            {"data": {}},
            {"data": {"total_credits": 10, "total_usage": "unknown"}},
        ):
            with self.subTest(payload=payload):
                adapter = OpenRouterAdapter(RecordedTransport([payload]))
                with self.assertRaises(ProviderError):
                    adapter.fetch_balance("management-secret", {})

    def test_transport_rejects_redirect_without_forwarding_authorization(self) -> None:
        redirected_requests: list[str | None] = []
        initial_authorization: list[str | None] = []

        class DestinationHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                redirected_requests.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"data": {}}')

            def log_message(self, format: str, *args: Any) -> None:
                pass

        destination = ThreadingHTTPServer(("127.0.0.1", 0), DestinationHandler)
        destination_url = f"http://127.0.0.1:{destination.server_port}/capture"

        class RedirectHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                initial_authorization.append(self.headers.get("Authorization"))
                self.send_response(302)
                self.send_header("Location", destination_url)
                self.end_headers()

            def log_message(self, format: str, *args: Any) -> None:
                pass

        redirect = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        threads = [
            threading.Thread(target=destination.serve_forever, daemon=True),
            threading.Thread(target=redirect.serve_forever, daemon=True),
        ]
        for thread in threads:
            thread.start()

        try:
            with (
                patch.object(
                    openrouter_module,
                    "BASE_URL",
                    f"http://127.0.0.1:{redirect.server_port}",
                ),
                self.assertRaisesRegex(ProviderError, "HTTP 302"),
            ):
                OpenRouterTransport().request(
                    "GET", "/keys/example", "management-secret"
                )
        finally:
            redirect.shutdown()
            destination.shutdown()
            redirect.server_close()
            destination.server_close()
            for thread in threads:
                thread.join()

        self.assertEqual(["Bearer management-secret"], initial_authorization)
        self.assertEqual([], redirected_requests)

    def test_parses_individual_key_usage_without_losing_scope(self) -> None:
        transport = RecordedTransport(
            [
                key_payload(
                    usage=6.25,
                    expires_at="2027-12-31T23:59:59Z",
                )
            ]
        )
        adapter = OpenRouterAdapter(transport)

        snapshot = adapter.fetch_usage("management-secret", {"key_hash": "A" * 64})

        self.assertEqual(6.25, snapshot.used)
        self.assertEqual(20.0, snapshot.limit)
        self.assertEqual(13.75, snapshot.remaining)
        self.assertEqual("USD", snapshot.unit)
        self.assertIsNone(snapshot.period_start)
        self.assertIsNone(snapshot.period_end)
        self.assertEqual("2027-12-31T23:59:59Z", snapshot.expires_at)
        self.assertEqual("individual_key", snapshot.provider_status["scope"])
        self.assertIsNone(snapshot.provider_status["limit_reset"])
        self.assertEqual(
            ("GET", f"/keys/{'a' * 64}", "management-secret", None),
            transport.calls[0],
        )

    def test_missing_or_malformed_usage_never_becomes_zero(self) -> None:
        for payload in ({"data": {}}, {"data": {"usage": "unknown"}}):
            with self.subTest(payload=payload):
                adapter = OpenRouterAdapter(RecordedTransport([payload]))
                with self.assertRaisesRegex(ProviderError, "usage"):
                    adapter.fetch_usage("management-secret", {"key_hash": "a" * 64})

    def test_malformed_billing_period_is_rejected(self) -> None:
        adapter = OpenRouterAdapter(
            RecordedTransport([key_payload(usage=1, limit_reset="not-a-date")])
        )

        with self.assertRaisesRegex(ProviderError, "limit_reset"):
            adapter.fetch_usage("management-secret", {"key_hash": "a" * 64})

    def test_invalid_or_out_of_range_expiration_is_rejected(self) -> None:
        for value in (
            "not-a-date",
            "2027-12-31T23:59:59",
            "0001-01-01T00:00:00+14:00",
            "9999-12-31T23:59:59-14:00",
        ):
            with self.subTest(expires_at=value):
                adapter = OpenRouterAdapter(
                    RecordedTransport(
                        [key_payload(usage=1, expires_at=value)]
                    )
                )
                with self.assertRaisesRegex(ProviderError, "expires_at"):
                    adapter.fetch_usage(
                        "management-secret", {"key_hash": "a" * 64}
                    )

    def test_monthly_reset_cadence_becomes_current_utc_billing_period(self) -> None:
        adapter = OpenRouterAdapter(
            RecordedTransport([key_payload(usage=1, limit_reset="monthly")])
        )

        with patch.object(
            openrouter_module,
            "_utc_now",
            return_value=datetime(2026, 10, 13, 6, 30, tzinfo=UTC),
        ):
            snapshot = adapter.fetch_usage(
                "management-secret", {"key_hash": "a" * 64}
            )

        self.assertEqual("2026-10-01T00:00:00+00:00", snapshot.period_start)
        self.assertEqual("2026-11-01T00:00:00+00:00", snapshot.period_end)
        self.assertEqual("monthly", snapshot.provider_status["limit_reset"])

    def test_daily_and_weekly_reset_cadences_use_utc_boundaries(self) -> None:
        cases = (
            (
                "daily",
                "2026-10-13T00:00:00+00:00",
                "2026-10-14T00:00:00+00:00",
            ),
            (
                "weekly",
                "2026-10-12T00:00:00+00:00",
                "2026-10-19T00:00:00+00:00",
            ),
        )
        for cadence, expected_start, expected_end in cases:
            with self.subTest(cadence=cadence):
                adapter = OpenRouterAdapter(
                    RecordedTransport(
                        [key_payload(usage=1, limit_reset=cadence)]
                    )
                )
                with patch.object(
                    openrouter_module,
                    "_utc_now",
                    return_value=datetime(2026, 10, 13, 23, 59, tzinfo=UTC),
                ):
                    snapshot = adapter.fetch_usage(
                        "management-secret", {"key_hash": "a" * 64}
                    )
                self.assertEqual(expected_start, snapshot.period_start)
                self.assertEqual(expected_end, snapshot.period_end)

    def test_monthly_reset_rolls_december_into_next_year(self) -> None:
        adapter = OpenRouterAdapter(
            RecordedTransport([key_payload(usage=1, limit_reset="monthly")])
        )

        with patch.object(
            openrouter_module,
            "_utc_now",
            return_value=datetime(2026, 12, 31, 23, 59, tzinfo=UTC),
        ):
            snapshot = adapter.fetch_usage(
                "management-secret", {"key_hash": "a" * 64}
            )

        self.assertEqual("2026-12-01T00:00:00+00:00", snapshot.period_start)
        self.assertEqual("2027-01-01T00:00:00+00:00", snapshot.period_end)

    def test_capabilities_and_actions_match_the_documented_api(self) -> None:
        adapter = OpenRouterAdapter(RecordedTransport([]))
        self.assertIn(CAN_FETCH_USAGE, adapter.capabilities)
        self.assertIn(CAN_DISABLE_KEY, adapter.capabilities)
        self.assertIn(CAN_IDENTIFY_INDIVIDUAL_KEY_USAGE, adapter.capabilities)
        self.assertEqual(("disable",), adapter.actions)


class OpenRouterProtectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.vault = FakeVault()
        self.store = Store(Path(self.temp.name) / "state.db", self.vault)

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def _credential(self) -> dict[str, Any]:
        return self.store.create_credential(
            provider="openrouter",
            name="Freebie 3",
            secret="management-secret",
            threshold=5.0,
            auto_protect=True,
            provider_metadata={"key_hash": "a" * 64},
            protection_action="disable",
        )

    def test_threshold_is_rechecked_then_disable_is_verified(self) -> None:
        transport = RecordedTransport(
            [
                key_payload(usage=5.1),
                key_payload(usage=5.2),
                {"data": {"disabled": True}},
                key_payload(usage=5.2, disabled=True),
            ]
        )
        adapter = OpenRouterAdapter(transport)
        notifications = CapturingNotifications()
        service = ProtectionService(
            self.store, ProviderRegistry([adapter]), notifications
        )
        credential = self._credential()

        outcome = service.check(credential["id"])

        self.assertTrue(outcome["threshold_crossed"])
        self.assertEqual({"action": "disable", "verified": True}, outcome["action"])
        self.assertEqual(
            "disabled", self.store.get_credential(credential["id"])["status"]
        )
        self.assertEqual(2, len(self.store.usage_history(credential["id"])))
        self.assertEqual(
            ["GET", "GET", "PATCH", "GET"],
            [call[0] for call in transport.calls],
        )
        self.assertEqual({"disabled": True}, transport.calls[2][3])
        events = self.store.history(credential["id"])
        self.assertEqual("success", events[0]["result"])
        self.assertEqual("protection_action", events[0]["event_type"])
        self.assertEqual("success", notifications.deliveries[0]["event"]["result"])
        self.assertIn("was disabled", notifications.deliveries[0]["message"])

    def test_failed_provider_action_is_recorded_as_action_failed(self) -> None:
        transport = RecordedTransport(
            [
                key_payload(usage=6.0),
                key_payload(usage=6.1),
                ProviderError("OpenRouter returned HTTP 503"),
            ]
        )
        notifications = CapturingNotifications()
        service = ProtectionService(
            self.store,
            ProviderRegistry([OpenRouterAdapter(transport)]),
            notifications,
        )
        credential = self._credential()

        with self.assertRaisesRegex(ProviderError, "HTTP 503"):
            service.check(credential["id"])

        self.assertEqual(
            "action_failed", self.store.get_credential(credential["id"])["status"]
        )
        event = self.store.history(credential["id"])[0]
        self.assertEqual("action_failed", event["result"])
        self.assertEqual(
            "action_failed", notifications.deliveries[0]["event"]["result"]
        )
        self.assertIn("Manual action is required", notifications.deliveries[0]["message"])

    def test_second_read_below_threshold_cancels_protection(self) -> None:
        transport = RecordedTransport([key_payload(usage=5.1), key_payload(usage=4.9)])
        service = ProtectionService(
            self.store, ProviderRegistry([OpenRouterAdapter(transport)])
        )
        credential = self._credential()

        outcome = service.check(credential["id"])

        self.assertFalse(outcome["threshold_crossed"])
        self.assertEqual("below_threshold", outcome["verification"])
        self.assertEqual(
            "watching", self.store.get_credential(credential["id"])["status"]
        )
        self.assertEqual(["GET", "GET"], [call[0] for call in transport.calls])

    def test_notify_only_threshold_is_rechecked_and_alerted_without_mutation(
        self,
    ) -> None:
        transport = RecordedTransport(
            [key_payload(usage=5.1), key_payload(usage=5.2)]
        )
        notifications = CapturingNotifications()
        service = ProtectionService(
            self.store,
            ProviderRegistry([OpenRouterAdapter(transport)]),
            notifications,
        )
        credential = self.store.create_credential(
            provider="openrouter",
            name="Alert only",
            secret="management-secret",
            threshold=5.0,
            auto_protect=True,
            provider_metadata={"key_hash": "a" * 64},
            protection_action="notify_only",
        )

        outcome = service.check(credential["id"])

        self.assertTrue(outcome["threshold_crossed"])
        self.assertEqual("confirmed", outcome["verification"])
        self.assertEqual("notify_only", outcome["action"])
        self.assertEqual(
            "critical", self.store.get_credential(credential["id"])["status"]
        )
        self.assertEqual(["GET", "GET"], [call[0] for call in transport.calls])
        self.assertEqual(2, len(self.store.usage_history(credential["id"])))
        event = self.store.history(credential["id"])[0]
        self.assertEqual("protection_action", event["event_type"])
        self.assertEqual("notify_only", event["result"])
        self.assertEqual(
            {
                "action": "notify_only",
                "verified": True,
                "threshold": 5.0,
                "trigger": "automatic_threshold",
                "credential_identity_revision": (
                    service._credential_identity_revision(credential)
                ),
            },
            event["details"],
        )
        self.assertEqual(
            "notify_only", notifications.deliveries[0]["event"]["result"]
        )
        self.assertIn(
            "No provider action was taken", notifications.deliveries[0]["message"]
        )

    def test_notify_only_second_read_below_threshold_cancels_alert(self) -> None:
        transport = RecordedTransport(
            [key_payload(usage=5.1), key_payload(usage=4.9)]
        )
        notifications = CapturingNotifications()
        service = ProtectionService(
            self.store,
            ProviderRegistry([OpenRouterAdapter(transport)]),
            notifications,
        )
        credential = self.store.create_credential(
            provider="openrouter",
            name="Alert only",
            secret="management-secret",
            threshold=5.0,
            auto_protect=True,
            provider_metadata={"key_hash": "a" * 64},
            protection_action="notify_only",
        )

        outcome = service.check(credential["id"])

        self.assertFalse(outcome["threshold_crossed"])
        self.assertEqual("below_threshold", outcome["verification"])
        self.assertEqual(["GET", "GET"], [call[0] for call in transport.calls])
        self.assertEqual([], notifications.deliveries)

    def test_notify_only_threshold_alert_is_suppressed_until_rearmed(self) -> None:
        transport = RecordedTransport(
            [
                key_payload(usage=5.1),
                key_payload(usage=5.2),
                key_payload(usage=5.3),
                key_payload(usage=5.4),
                key_payload(usage=4.9),
                key_payload(usage=5.5),
                key_payload(usage=5.6),
            ]
        )
        notifications = CapturingNotifications(self.store)
        service = ProtectionService(
            self.store,
            ProviderRegistry([OpenRouterAdapter(transport)]),
            notifications,
        )
        credential = self.store.create_credential(
            provider="openrouter",
            name="Alert only",
            secret="management-secret",
            threshold=5.0,
            auto_protect=True,
            provider_metadata={"key_hash": "a" * 64},
            protection_action="notify_only",
        )

        first = service.check(credential["id"], scheduled=True)
        repeated = service.check(credential["id"], scheduled=True)
        below = service.check(credential["id"], scheduled=True)
        rearmed = service.check(credential["id"], scheduled=True)

        self.assertEqual("notify_only", first["action"])
        self.assertEqual("notify_only_already_alerted", repeated["action"])
        self.assertFalse(below["threshold_crossed"])
        self.assertEqual("notify_only", rearmed["action"])
        self.assertEqual(2, len(notifications.deliveries))
        notify_events = [
            event
            for event in self.store.history(credential["id"])
            if event["event_type"] == "protection_action"
            and event["result"] == "notify_only"
        ]
        self.assertEqual(2, len(notify_events))

    def test_notify_only_threshold_retries_after_failed_notification(self) -> None:
        transport = RecordedTransport(
            [
                key_payload(usage=5.1),
                key_payload(usage=5.2),
                key_payload(usage=5.3),
                key_payload(usage=5.4),
                key_payload(usage=5.5),
                key_payload(usage=5.6),
            ]
        )
        attempts = 0

        class Response:
            status = 200

            def close(self) -> None:
                pass

        def send(_request: Any, _timeout: float) -> Response:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise urllib.error.URLError("offline")
            return Response()

        self.store.update_notification_config(
            {
                "server_url": "https://ntfy.example",
                "topic": "keyguard-home",
                "enabled": True,
            }
        )
        service = ProtectionService(
            self.store,
            ProviderRegistry([OpenRouterAdapter(transport)]),
            NtfyNotifier(self.store, sender=send),
        )
        credential = self.store.create_credential(
            provider="openrouter",
            name="Alert retry",
            secret="management-secret",
            threshold=5.0,
            auto_protect=True,
            provider_metadata={"key_hash": "a" * 64},
            protection_action="notify_only",
        )

        failed_delivery = service.check(credential["id"], scheduled=True)
        retried_delivery = service.check(credential["id"], scheduled=True)
        suppressed_repeat = service.check(credential["id"], scheduled=True)

        self.assertEqual("notify_only", failed_delivery["action"])
        self.assertEqual("notify_only", retried_delivery["action"])
        self.assertEqual(
            "notify_only_already_alerted", suppressed_repeat["action"]
        )
        self.assertEqual(2, attempts)
        deliveries = [
            event
            for event in self.store.history(credential["id"])
            if event["event_type"] == "notification_delivery"
        ]
        self.assertEqual(
            ["success", "failed"],
            [event["result"] for event in deliveries],
        )

    def test_notify_only_without_delivery_attempt_stays_suppressed(self) -> None:
        transport = RecordedTransport(
            [
                key_payload(usage=5.1),
                key_payload(usage=5.2),
                key_payload(usage=5.3),
                key_payload(usage=5.4),
            ]
        )
        service = ProtectionService(
            self.store,
            ProviderRegistry([OpenRouterAdapter(transport)]),
            NtfyNotifier(self.store),
        )
        credential = self.store.create_credential(
            provider="openrouter",
            name="Notifications disabled",
            secret="management-secret",
            threshold=5.0,
            auto_protect=True,
            provider_metadata={"key_hash": "a" * 64},
            protection_action="notify_only",
        )

        first = service.check(credential["id"], scheduled=True)
        repeated = service.check(credential["id"], scheduled=True)

        self.assertEqual("notify_only", first["action"])
        self.assertEqual("notify_only_already_alerted", repeated["action"])
        self.assertNotIn(
            "notification_delivery",
            [
                event["event_type"]
                for event in self.store.history(credential["id"])
            ],
        )

    def test_manual_notify_only_does_not_suppress_next_threshold_alert(self) -> None:
        transport = RecordedTransport(
            [
                key_payload(usage=4.0),
                key_payload(usage=5.1),
                key_payload(usage=5.2),
            ]
        )
        notifications = CapturingNotifications(self.store)
        service = ProtectionService(
            self.store,
            ProviderRegistry([OpenRouterAdapter(transport)]),
            notifications,
        )
        credential = self.store.create_credential(
            provider="openrouter",
            name="Manual then automatic",
            secret="management-secret",
            threshold=5.0,
            auto_protect=True,
            provider_metadata={"key_hash": "a" * 64},
            protection_action="notify_only",
        )

        manual = service.check(credential["id"], force_protect=True)
        automatic = service.check(credential["id"], scheduled=True)

        self.assertEqual("notify_only", manual["action"])
        self.assertEqual("notify_only", automatic["action"])
        self.assertEqual(2, len(notifications.deliveries))
        notify_events = [
            event
            for event in self.store.history(credential["id"])
            if event["event_type"] == "protection_action"
            and event["result"] == "notify_only"
        ]
        self.assertEqual(
            ["automatic_threshold", "manual"],
            [event["details"]["trigger"] for event in notify_events],
        )

    def test_new_provider_identity_gets_its_own_threshold_alert(self) -> None:
        transport = RecordedTransport(
            [
                key_payload(usage=5.1),
                key_payload(usage=5.2),
                key_payload(usage=5.3),
                key_payload(usage=5.4),
            ]
        )
        notifications = CapturingNotifications(self.store)
        service = ProtectionService(
            self.store,
            ProviderRegistry([OpenRouterAdapter(transport)]),
            notifications,
        )
        credential = self.store.create_credential(
            provider="openrouter",
            name="Replace monitored key",
            secret="management-secret",
            threshold=5.0,
            auto_protect=True,
            provider_metadata={"key_hash": "a" * 64},
            protection_action="notify_only",
        )

        first = service.check(credential["id"], scheduled=True)
        updated = self.store.update_credential(
            credential["id"],
            {"provider_metadata": {"key_hash": "b" * 64}},
        )
        second = service.check(credential["id"], scheduled=True)

        self.assertIsNotNone(updated)
        self.assertEqual("notify_only", first["action"])
        self.assertEqual("notify_only", second["action"])
        self.assertEqual(2, len(notifications.deliveries))
        identities = {
            event["details"]["credential_identity_revision"]
            for event in self.store.history(credential["id"])
            if event["event_type"] == "protection_action"
            and event["result"] == "notify_only"
        }
        self.assertEqual(2, len(identities))

    def test_notify_only_verification_observes_external_disable(self) -> None:
        transport = RecordedTransport(
            [
                key_payload(usage=5.1),
                key_payload(usage=5.2, disabled=True),
            ]
        )
        notifications = CapturingNotifications()
        service = ProtectionService(
            self.store,
            ProviderRegistry([OpenRouterAdapter(transport)]),
            notifications,
        )
        credential = self.store.create_credential(
            provider="openrouter",
            name="Externally disabled",
            secret="management-secret",
            threshold=5.0,
            auto_protect=True,
            provider_metadata={"key_hash": "a" * 64},
            protection_action="notify_only",
        )

        outcome = service.check(credential["id"], scheduled=True)

        self.assertEqual("already_disabled", outcome["action"])
        self.assertEqual(
            "disabled", self.store.get_credential(credential["id"])["status"]
        )
        event = self.store.history(credential["id"])[0]
        self.assertEqual("credential_invalid_or_revoked", event["event_type"])
        self.assertEqual("disabled_externally", event["result"])
        self.assertNotIn(
            "notify_only",
            [
                event["result"]
                for event in self.store.history(credential["id"])
                if event["event_type"] == "protection_action"
            ],
        )
        self.assertIn(
            "disabled at the provider", notifications.deliveries[0]["message"]
        )

    def test_verification_read_failure_does_not_claim_action_failure(self) -> None:
        transport = RecordedTransport(
            [
                key_payload(usage=6.0),
                ProviderError("OpenRouter returned HTTP 503"),
            ]
        )
        service = ProtectionService(
            self.store, ProviderRegistry([OpenRouterAdapter(transport)])
        )
        credential = self._credential()

        with self.assertRaisesRegex(ProviderError, "HTTP 503"):
            service.check(credential["id"])

        self.assertEqual(
            "critical_pending_verification",
            self.store.get_credential(credential["id"])["status"],
        )
        event = self.store.history(credential["id"])[0]
        self.assertEqual("usage_verification_failed", event["event_type"])
        self.assertEqual("failed", event["result"])
        self.assertEqual(["GET", "GET"], [call[0] for call in transport.calls])

    def test_disabled_provider_key_stays_disabled_after_check(self) -> None:
        transport = RecordedTransport([key_payload(usage=4.0, disabled=True)])
        service = ProtectionService(
            self.store, ProviderRegistry([OpenRouterAdapter(transport)])
        )
        credential = self._credential()

        outcome = service.check(credential["id"])

        self.assertFalse(outcome["threshold_crossed"])
        self.assertEqual(
            "disabled", self.store.get_credential(credential["id"])["status"]
        )

    def test_overlapping_protection_requests_execute_one_provider_mutation(
        self,
    ) -> None:
        transport = BlockingTransport(
            [
                key_payload(usage=6.0),
                {"data": {"disabled": True}},
                key_payload(usage=6.0, disabled=True),
            ]
        )
        service = ProtectionService(
            self.store, ProviderRegistry([OpenRouterAdapter(transport)])
        )
        credential = self._credential()
        results: list[dict[str, Any]] = []

        first = threading.Thread(
            target=lambda: results.append(
                service.check(credential["id"], force_protect=True)
            )
        )
        second = threading.Thread(
            target=lambda: results.append(
                service.check(credential["id"], force_protect=True)
            )
        )
        first.start()
        self.assertTrue(transport.first_call_started.wait(timeout=1))
        second.start()

        self.assertEqual(0, len(transport.calls))
        transport.release_first_call.set()
        first.join(timeout=2)
        second.join(timeout=2)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(2, len(results))
        self.assertEqual(1, [call[0] for call in transport.calls].count("PATCH"))
        self.assertEqual(3, len(transport.calls))
        self.assertTrue(
            any(result["action"] == "already_disabled" for result in results)
        )

    def test_credential_mutation_waits_for_in_flight_check(self) -> None:
        transport = BlockingTransport([key_payload(usage=4.0)])
        service = ProtectionService(
            self.store, ProviderRegistry([OpenRouterAdapter(transport)])
        )
        credential = self._credential()
        mutation_started = threading.Event()
        mutation_finished = threading.Event()

        check = threading.Thread(target=lambda: service.check(credential["id"]))

        def pause_credential() -> None:
            mutation_started.set()
            with service.credential_operation(credential["id"]):
                self.store.set_paused(credential["id"], True)
            mutation_finished.set()

        mutation = threading.Thread(target=pause_credential)
        check.start()
        self.assertTrue(transport.first_call_started.wait(timeout=1))
        mutation.start()
        self.assertTrue(mutation_started.wait(timeout=1))
        self.assertFalse(mutation_finished.wait(timeout=0.05))

        transport.release_first_call.set()
        check.join(timeout=2)
        mutation.join(timeout=2)

        self.assertFalse(check.is_alive())
        self.assertFalse(mutation.is_alive())
        self.assertTrue(mutation_finished.is_set())
        self.assertTrue(self.store.get_credential(credential["id"])["paused"])


if __name__ == "__main__":
    unittest.main()

