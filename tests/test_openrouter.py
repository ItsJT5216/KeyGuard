from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from keyguard.protection import ProtectionService
from keyguard.providers import ProviderRegistry
from keyguard.providers.base import (
    CAN_DISABLE_KEY,
    CAN_FETCH_USAGE,
    CAN_IDENTIFY_INDIVIDUAL_KEY_USAGE,
    ProviderError,
)
from keyguard.providers.openrouter import OpenRouterAdapter
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
        service = ProtectionService(self.store, ProviderRegistry([adapter]))
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

    def test_failed_provider_action_is_recorded_as_action_failed(self) -> None:
        transport = RecordedTransport(
            [
                key_payload(usage=6.0),
                key_payload(usage=6.1),
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
            "action_failed", self.store.get_credential(credential["id"])["status"]
        )
        event = self.store.history(credential["id"])[0]
        self.assertEqual("action_failed", event["result"])

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


if __name__ == "__main__":
    unittest.main()
