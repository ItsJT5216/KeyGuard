from __future__ import annotations

import logging
import math
import random
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from typing import Any

from .protection import ProtectionService
from .providers.base import ProviderError
from .store import Store
from .notifications import NtfyNotifier

LOGGER = logging.getLogger("keyguard.scheduler")
MAX_CONCURRENT_CHECKS = 4

DEFAULT_POLLING_CONFIG: dict[str, float] = {
    "quiet_distance": 10.0,
    "watch_distance": 5.0,
    "accelerated_distance": 2.0,
    "critical_distance": 0.5,
    "quiet_interval_seconds": 4 * 60 * 60,
    "watch_interval_seconds": 60 * 60,
    "accelerated_interval_seconds": 15 * 60,
    "critical_interval_seconds": 5 * 60,
    "urgent_interval_seconds": 60,
    "safety_margin_seconds": 30,
    "jitter_fraction": 0.1,
}

DISTANCE_KEYS = (
    "quiet_distance",
    "watch_distance",
    "accelerated_distance",
    "critical_distance",
)
INTERVAL_KEYS = (
    "quiet_interval_seconds",
    "watch_interval_seconds",
    "accelerated_interval_seconds",
    "critical_interval_seconds",
    "urgent_interval_seconds",
)


class PollingConfigError(ValueError):
    pass


def _number(value: Any, field: str, *, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PollingConfigError(f"{field} must be a number")
    number = float(value)
    if not math.isfinite(number) or number < 0 or number > maximum:
        raise PollingConfigError(f"{field} is outside the supported range")
    return number


def normalize_polling_config(value: Any) -> dict[str, float]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise PollingConfigError("polling must be an object")
    unknown = set(value) - set(DEFAULT_POLLING_CONFIG)
    if unknown:
        raise PollingConfigError(f"Unknown polling option: {min(unknown)}")
    result = dict(DEFAULT_POLLING_CONFIG)
    for key in DISTANCE_KEYS:
        if key in value:
            result[key] = _number(value[key], key, maximum=1_000_000_000)
    for key in INTERVAL_KEYS:
        if key in value:
            result[key] = _number(value[key], key, maximum=7 * 24 * 60 * 60)
            if result[key] < 1:
                raise PollingConfigError(f"{key} must be at least one second")
    if "safety_margin_seconds" in value:
        result["safety_margin_seconds"] = _number(
            value["safety_margin_seconds"],
            "safety_margin_seconds",
            maximum=24 * 60 * 60,
        )
    if "jitter_fraction" in value:
        result["jitter_fraction"] = _number(
            value["jitter_fraction"], "jitter_fraction", maximum=0.5
        )
    if not all(result[left] > result[right] for left, right in pairwise(DISTANCE_KEYS)):
        raise PollingConfigError("Polling distances must decrease toward the threshold")
    if not all(
        result[left] >= result[right] for left, right in pairwise(INTERVAL_KEYS)
    ):
        raise PollingConfigError(
            "Polling intervals must not increase toward the threshold"
        )
    return result


@dataclass(frozen=True)
class PollingPlan:
    tier: str
    interval_seconds: int
    burn_rate_per_second: float | None
    estimated_seconds_to_threshold: float | None


class AdaptiveScheduler:
    def __init__(
        self,
        store: Store,
        protection: ProtectionService,
        *,
        jitter: Callable[[float, float], float] = random.uniform,
        notifications: NtfyNotifier | None = None,
    ) -> None:
        self.store = store
        self.protection = protection
        self._jitter = jitter
        self.notifications = notifications
        self._wake = threading.Event()

    @staticmethod
    def _time(value: str) -> datetime:
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)

    @staticmethod
    def _distance_plan(distance: float, config: dict[str, float]) -> tuple[str, int]:
        if distance > config["quiet_distance"]:
            return "quiet", int(config["quiet_interval_seconds"])
        if distance > config["watch_distance"]:
            return "watching", int(config["watch_interval_seconds"])
        if distance > config["accelerated_distance"]:
            return "accelerated", int(config["accelerated_interval_seconds"])
        if distance > config["critical_distance"]:
            return "critical", int(config["critical_interval_seconds"])
        return "urgent", int(config["urgent_interval_seconds"])

    def plan(
        self,
        credential: dict[str, Any],
        snapshot: dict[str, Any],
        history: list[dict[str, Any]],
    ) -> PollingPlan:
        config = normalize_polling_config(credential.get("polling_config"))
        threshold = credential.get("threshold")
        if threshold is None:
            tier = "quiet"
            interval = int(config["quiet_interval_seconds"])
        else:
            distance = max(float(threshold) - float(snapshot["used"]), 0.0)
            tier, interval = self._distance_plan(distance, config)

        burn_rate: float | None = None
        estimated: float | None = None
        checked_at = self._time(snapshot["checked_at"])
        previous = next(
            (
                item
                for item in history
                if item.get("success")
                and item.get("checked_at") != snapshot["checked_at"]
                and item.get("used") is not None
            ),
            None,
        )
        if previous is not None and threshold is not None and distance > 0:
            elapsed = (checked_at - self._time(previous["checked_at"])).total_seconds()
            delta = float(snapshot["used"]) - float(previous["used"])
            if elapsed > 0 and delta > 0:
                burn_rate = delta / elapsed
                estimated = distance / burn_rate
                safe_window = max(
                    estimated - config["safety_margin_seconds"],
                    config["urgent_interval_seconds"],
                )
                if safe_window < interval:
                    candidates = [
                        ("quiet", int(config["quiet_interval_seconds"])),
                        ("watching", int(config["watch_interval_seconds"])),
                        ("accelerated", int(config["accelerated_interval_seconds"])),
                        ("critical", int(config["critical_interval_seconds"])),
                        ("urgent", int(config["urgent_interval_seconds"])),
                    ]
                    tier, interval = next(
                        (
                            (name, seconds)
                            for name, seconds in candidates
                            if seconds <= safe_window
                        ),
                        ("urgent", int(config["urgent_interval_seconds"])),
                    )
                    tier = f"burn_{tier}"

        if interval > config["critical_interval_seconds"]:
            spread = interval * config["jitter_fraction"]
            interval = max(
                int(config["urgent_interval_seconds"]),
                round(interval + self._jitter(-spread, spread)),
            )
            if estimated is not None:
                interval = min(
                    interval,
                    max(
                        int(config["urgent_interval_seconds"]),
                        int(estimated - config["safety_margin_seconds"]),
                    ),
                )
        return PollingPlan(tier, interval, burn_rate, estimated)

    def schedule_snapshot(
        self, credential_id: str, snapshot: dict[str, Any]
    ) -> PollingPlan | None:
        credential = self.store.get_credential(credential_id)
        if credential is None:
            return None
        history = self.store.usage_history(credential_id)
        plan = self.plan(credential, snapshot, history)
        previous_state = self.store.get_scheduler_state(credential_id) or {}
        previous_group = previous_state.get("notification_tier_group")
        current_group = self._tier_group(plan.tier)
        checked_at = self._time(snapshot["checked_at"])
        next_check = checked_at + timedelta(seconds=plan.interval_seconds)
        self.store.set_scheduler_state(
            credential_id,
            last_check_at=checked_at.isoformat(),
            next_check_at=next_check.isoformat(),
            current_interval_seconds=plan.interval_seconds,
            polling_tier=plan.tier,
            consecutive_failures=0,
            notification_tier_group=current_group,
        )
        self._notify_tier_transition(credential, snapshot, previous_group, plan)
        return plan

    @staticmethod
    def _tier_group(tier: str | None) -> str | None:
        value = (tier or "").removeprefix("burn_")
        if value in {"critical", "urgent"}:
            return "critical"
        if value == "accelerated":
            return "accelerated"
        return None

    def _notify_tier_transition(
        self,
        credential: dict[str, Any],
        snapshot: dict[str, Any],
        previous_group: str | None,
        plan: PollingPlan,
    ) -> None:
        group = self._tier_group(plan.tier)
        if group is None or group == previous_group:
            return
        event = self.store.record_event(
            credential["id"],
            "polling_tier_changed",
            group,
            {
                "from": previous_group,
                "to": plan.tier,
                "interval_seconds": plan.interval_seconds,
            },
        )
        if self.notifications is None:
            return
        remaining = snapshot.get("remaining")
        unit = snapshot.get("unit") or ""
        amount = (
            f"{remaining:g} {unit} remaining"
            if isinstance(remaining, (int, float))
            else "the protection threshold is approaching"
        )
        self.notifications.deliver_event(
            credential,
            event,
            f"{credential['name']} has {amount}. Polling increased to every "
            f"{plan.interval_seconds // 60 or 1} minute(s).",
            priority="high" if group == "critical" else "default",
            tags="warning,chart_with_upwards_trend",
        )

    def schedule_outcome(
        self, credential_id: str, outcome: dict[str, Any]
    ) -> PollingPlan | None:
        snapshot = outcome.get("snapshot")
        if not isinstance(snapshot, dict):
            return None
        credential = self.store.get_credential(credential_id)
        if (
            credential is None
            or credential["paused"]
            or credential["status"]
            in {"disabled", "cleanup_required", "provisioning"}
        ):
            return None
        return self.schedule_snapshot(credential_id, snapshot)

    def schedule_now(self, credential_id: str) -> None:
        self.store.schedule_now(credential_id)
        self._wake.set()

    def wake(self) -> None:
        self._wake.set()

    def prepare_wait(self) -> None:
        self._wake.clear()

    def wait(self, timeout: float) -> None:
        self._wake.wait(timeout=timeout)

    def _schedule_failure(self, credential_id: str, now: datetime) -> None:
        state = self.store.get_scheduler_state(credential_id) or {}
        failures = int(state.get("consecutive_failures", 0)) + 1
        retry = min(60 * (2 ** min(failures - 1, 4)), 15 * 60)
        self.store.set_scheduler_state(
            credential_id,
            last_check_at=state.get("last_check_at"),
            next_check_at=(now + timedelta(seconds=retry)).isoformat(),
            current_interval_seconds=retry,
            polling_tier="error_retry",
            consecutive_failures=failures,
            notification_tier_group=state.get("notification_tier_group"),
        )
        if failures == 3:
            credential = self.store.get_credential(credential_id)
            if credential is not None:
                event = self.store.record_event(
                    credential_id,
                    "provider_failures_repeated",
                    "failed",
                    {"consecutive_failures": failures},
                )
                if self.notifications is not None:
                    self.notifications.deliver_event(
                        credential,
                        event,
                        f"{credential['name']} has failed three provider checks in a row.",
                        priority="high",
                        tags="warning,cloud",
                    )

    def _process_credential(self, credential: dict[str, Any], current: datetime) -> int:
        credential_id = credential["id"]
        with self.protection.credential_operation(credential_id):
            latest = self.store.get_credential(credential_id)
            if (
                latest is None
                or latest["paused"]
                or latest["status"]
                in {
                    "disabled",
                    "cleanup_required",
                    "provisioning",
                }
            ):
                return 0
            try:
                outcome = self.protection.check(credential_id, scheduled=True)
            except (ProviderError, RuntimeError):
                self._schedule_failure(credential_id, current)
            except KeyError:
                return 0
            else:
                self.schedule_outcome(credential_id, outcome)
        return 1

    def run_due_once(self, *, now: datetime | None = None) -> int:
        current = now or datetime.now(UTC)
        due = self.store.due_credentials(current.isoformat())
        if not due:
            return 0
        workers = min(MAX_CONCURRENT_CHECKS, len(due))
        with ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="keyguard-check"
        ) as executor:
            futures = [
                executor.submit(self._process_credential, credential, current)
                for credential in due
            ]
            return sum(future.result() for future in futures)

    def seconds_until_next_check(self, *, now: datetime | None = None) -> float:
        next_check = self.store.next_scheduled_check()
        if next_check is None:
            return 30.0
        current = now or datetime.now(UTC)
        remaining = (self._time(next_check) - current).total_seconds()
        return min(30.0, max(0.05, remaining))


class SchedulerRunner(threading.Thread):
    def __init__(self, scheduler: AdaptiveScheduler) -> None:
        super().__init__(name="keyguard-scheduler", daemon=True)
        self.scheduler = scheduler
        self._stopped = threading.Event()

    def stop(self) -> None:
        self._stopped.set()
        self.scheduler.wake()

    def run(self) -> None:
        while not self._stopped.is_set():
            try:
                self.scheduler.run_due_once()
                self.scheduler.prepare_wait()
                timeout = self.scheduler.seconds_until_next_check()
            except Exception:
                LOGGER.exception("Scheduler iteration failed")
                timeout = 30.0
            if not self._stopped.is_set():
                self.scheduler.wait(timeout=timeout)


