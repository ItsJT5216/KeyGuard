from __future__ import annotations

import threading
from typing import Any

from .providers import ProviderRegistry
from .providers.base import ProviderError, UsageSnapshot
from .store import Store


class ProtectionService:
    def __init__(self, store: Store, providers: ProviderRegistry) -> None:
        self.store = store
        self.providers = providers
        self._credential_locks: dict[str, threading.Lock] = {}
        self._credential_locks_guard = threading.Lock()

    def _credential_lock(self, credential_id: str) -> threading.Lock:
        with self._credential_locks_guard:
            return self._credential_locks.setdefault(credential_id, threading.Lock())

    def _capture(
        self, credential_id: str, secret: str, adapter: Any, metadata: dict[str, Any]
    ) -> UsageSnapshot:
        snapshot = adapter.fetch_usage(secret, metadata)
        self.store.record_usage_snapshot(credential_id, snapshot.as_dict())
        return snapshot

    def check(
        self, credential_id: str, *, force_protect: bool = False
    ) -> dict[str, Any]:
        # A scheduled check and a dashboard request may arrive together. Keep the
        # full verify-and-act transaction single-flight for each credential so
        # they cannot race into duplicate provider mutations.
        with self._credential_lock(credential_id):
            return self._check(credential_id, force_protect=force_protect)

    def _check(
        self, credential_id: str, *, force_protect: bool = False
    ) -> dict[str, Any]:
        credential = self.store.get_credential(credential_id)
        if credential is None:
            raise KeyError(credential_id)
        adapter = self.providers.get(credential["provider"])
        secret = self.store.get_secret(credential_id)
        if secret is None:
            raise ProviderError("Credential secret is unavailable")
        metadata = credential["provider_metadata"]
        try:
            first = self._capture(credential_id, secret, adapter, metadata)
        except ProviderError:
            self.store.set_runtime_status(credential_id, "error")
            self.store.record_event(credential_id, "usage_check_failed", "failed", {})
            raise

        threshold = credential["threshold"]
        crossed = threshold is not None and first.used >= threshold
        if not crossed and not force_protect:
            status = (
                "disabled"
                if first.provider_status.get("disabled") is True
                else "watching"
            )
            self.store.set_runtime_status(credential_id, status)
            self.store.record_event(
                credential_id,
                "usage_checked",
                "success",
                {"used": first.used, "unit": first.unit},
            )
            return {"snapshot": first.as_dict(), "threshold_crossed": False}

        if force_protect:
            self.store.record_event(
                credential_id,
                "manual_protection_requested",
                "pending",
                {"used": first.used, "unit": first.unit},
            )
        else:
            self.store.set_runtime_status(
                credential_id, "critical_pending_verification"
            )
            self.store.record_event(
                credential_id,
                "threshold_crossed",
                "pending_verification",
                {"used": first.used, "threshold": threshold, "unit": first.unit},
            )
        if not force_protect and not credential["auto_protect"]:
            self.store.set_runtime_status(credential_id, "critical")
            return {"snapshot": first.as_dict(), "threshold_crossed": True}
        if credential["protection_action"] == "notify_only":
            self.store.set_runtime_status(credential_id, "critical")
            return {
                "snapshot": first.as_dict(),
                "threshold_crossed": True,
                "action": "notify_only",
            }

        if force_protect:
            verified = first
        else:
            try:
                verified = self._capture(credential_id, secret, adapter, metadata)
            except ProviderError:
                self.store.record_event(
                    credential_id,
                    "usage_verification_failed",
                    "failed",
                    {"used": first.used, "threshold": threshold, "unit": first.unit},
                )
                raise
            if verified.used < threshold:
                status = (
                    "disabled"
                    if verified.provider_status.get("disabled") is True
                    else "watching"
                )
                self.store.set_runtime_status(credential_id, status)
                self.store.record_event(
                    credential_id,
                    "protection_cancelled",
                    "verification_below_threshold",
                    {"used": verified.used, "threshold": threshold},
                )
                return {
                    "snapshot": verified.as_dict(),
                    "threshold_crossed": False,
                    "verification": "below_threshold",
                }

        try:
            result = adapter.execute_action(
                credential["protection_action"], secret, metadata
            )
        except ProviderError:
            self.store.set_runtime_status(credential_id, "action_failed")
            self.store.record_event(
                credential_id,
                "protection_action",
                "action_failed",
                {"action": credential["protection_action"]},
            )
            raise

        self.store.set_runtime_status(credential_id, "disabled")
        self.store.record_event(
            credential_id,
            "protection_action",
            "success",
            {"action": credential["protection_action"], "verified": True},
        )
        return {
            "snapshot": verified.as_dict(),
            "threshold_crossed": True,
            "action": result,
        }
