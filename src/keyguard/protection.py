from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from .providers import ProviderRegistry
from .providers.base import ProviderError, UsageSnapshot
from .store import Store
from .notifications import NtfyNotifier


class ProtectionService:
    _LOCK_STRIPES = 64

    def __init__(
        self,
        store: Store,
        providers: ProviderRegistry,
        notifications: NtfyNotifier | None = None,
    ) -> None:
        self.store = store
        self.providers = providers
        self.notifications = notifications
        self._credential_locks = tuple(
            threading.RLock() for _ in range(self._LOCK_STRIPES)
        )

    @contextmanager
    def credential_operation(self, credential_id: str) -> Iterator[None]:
        """Serialize checks and mutations without retaining credential IDs forever."""
        lock = self._credential_locks[hash(credential_id) % self._LOCK_STRIPES]
        with lock:
            yield

    def _capture(
        self, credential_id: str, secret: str, adapter: Any, metadata: dict[str, Any]
    ) -> UsageSnapshot:
        snapshot = adapter.fetch_usage(secret, metadata)
        self.store.record_usage_snapshot(credential_id, snapshot.as_dict())
        return snapshot

    def check(
        self,
        credential_id: str,
        *,
        force_protect: bool = False,
        scheduled: bool = False,
    ) -> dict[str, Any]:
        with self.credential_operation(credential_id):
            return self._check(
                credential_id,
                force_protect=force_protect,
                scheduled=scheduled,
            )

    def _check(
        self,
        credential_id: str,
        *,
        force_protect: bool = False,
        scheduled: bool = False,
    ) -> dict[str, Any]:
        credential = self.store.get_credential(credential_id)
        if credential is None:
            raise KeyError(credential_id)
        if scheduled and (
            credential["paused"]
            or credential["status"] in {"disabled", "cleanup_required", "provisioning"}
        ):
            return {"threshold_crossed": False, "skipped": credential["status"]}
        if force_protect and credential["status"] == "disabled":
            return {"threshold_crossed": True, "action": "already_disabled"}
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
        if first.provider_status.get("disabled") is True:
            self.store.set_runtime_status(credential_id, "disabled")
            if credential["status"] != "disabled":
                event = self.store.record_event(
                    credential_id,
                    "credential_invalid_or_revoked",
                    "disabled_externally",
                    {},
                )
                if self.notifications is not None:
                    self.notifications.deliver_event(
                        credential,
                        event,
                        f"{credential['name']} is disabled at the provider.",
                        priority="high",
                        tags="warning,lock",
                    )
            return {
                "snapshot": first.as_dict(),
                "threshold_crossed": threshold is not None and first.used >= threshold,
                "action": "already_disabled",
            }
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

        latest = self.store.get_credential(credential_id)
        if latest is None:
            raise KeyError(credential_id)
        if latest["paused"] and not force_protect:
            return {
                "snapshot": verified.as_dict(),
                "threshold_crossed": True,
                "action": "paused",
            }
        if latest["status"] == "disabled":
            return {
                "snapshot": verified.as_dict(),
                "threshold_crossed": True,
                "action": "already_disabled",
            }

        try:
            result = adapter.execute_action(
                credential["protection_action"], secret, metadata
            )
        except ProviderError:
            self.store.set_runtime_status(credential_id, "action_failed")
            event = self.store.record_event(
                credential_id,
                "protection_action",
                "action_failed",
                {"action": credential["protection_action"]},
            )
            if self.notifications is not None:
                self.notifications.deliver_event(
                    credential,
                    event,
                    f"Unable to {credential['protection_action']} {credential['name']}. "
                    "Manual action is required.",
                    priority="urgent",
                    tags="x,rotating_light",
                )
            raise

        self.store.set_runtime_status(credential_id, "disabled")
        event = self.store.record_event(
            credential_id,
            "protection_action",
            "success",
            {"action": credential["protection_action"], "verified": True},
        )
        if self.notifications is not None:
            threshold_text = (
                f"{threshold:g} {verified.unit}"
                if isinstance(threshold, (int, float))
                else "the manual protection request"
            )
            self.notifications.deliver_event(
                credential,
                event,
                f"{credential['name']} was {credential['protection_action']}d "
                f"at {verified.used:g} {verified.unit}; trigger: {threshold_text}.",
                priority="high",
                tags="fire,shield",
            )
        return {
            "snapshot": verified.as_dict(),
            "threshold_crossed": True,
            "action": result,
        }

