from __future__ import annotations

import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import patch

from keyguard.protection import ProtectionService
from keyguard.providers import ProviderRegistry
from keyguard.providers import openrouter as openrouter_module
from keyguard.providers.base import (
    CAN_DISABLE_KEY,
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
    def __init__(self) -> None:
        self.deliveries: list[dict[str, Any]] = []

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
    *, usage: float, disabled: bool = False, limit: float = 20.0
) -> dict[str, Any]:
    return {
        "data": {
            "hash": "a" * 64,
            "usage": usage,
            "limit": limit,
            "limit_remaining": max(limit - usage, 0),
            "limit_reset": None,
            "disabled": disabled,
        }
    }


class OpenRouterAdapterTests(unittest.TestCase):
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
        transport = RecordedTransport([key_payload(usage=6.25)])
        adapter = OpenRouterAdapter(transport)

        snapshot = adapter.fetch_usage("management-secret", {"key_hash": "A" * 64})

        self.assertEqual(6.25, snapshot.used)
        self.assertEqual(20.0, snapshot.limit)
        self.assertEqual(13.75, snapshot.remaining)
        self.assertEqual("USD", snapshot.unit)
        self.assertEqual("individual_key", snapshot.provider_status["scope"])
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

