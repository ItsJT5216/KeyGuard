from __future__ import annotations

import tempfile
import threading
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from keyguard.providers.base import ProviderError
from keyguard.scheduler import (
    AdaptiveScheduler,
    PollingConfigError,
    normalize_polling_config,
)
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


class FakeProtection:
    def __init__(self, outcome: dict[str, Any] | Exception) -> None:
        self.outcome = outcome
        self.calls: list[str] = []

    @contextmanager
    def credential_operation(self, credential_id: str):
        yield

    def check(self, credential_id: str, *, scheduled: bool = False) -> dict[str, Any]:
        self.calls.append(credential_id)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


class ConcurrentProtection(FakeProtection):
    def __init__(self) -> None:
        super().__init__({})
        self.barrier = threading.Barrier(2)
        self.state_lock = threading.Lock()
        self.active = 0
        self.max_active = 0

    def check(self, credential_id: str, *, scheduled: bool = False) -> dict[str, Any]:
        with self.state_lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            self.barrier.wait(timeout=2)
            return {"snapshot": snapshot(datetime.now(UTC), 1.0)}
        finally:
            with self.state_lock:
                self.active -= 1


def snapshot(checked_at: datetime, used: float) -> dict[str, Any]:
    return {
        "checked_at": checked_at.isoformat(),
        "used": used,
        "limit": 20.0,
        "remaining": max(20.0 - used, 0.0),
        "unit": "USD",
        "provider_status": {},
    }


class AdaptiveSchedulerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state.db"
        self.vault = FakeVault()
        self.store = Store(self.path, self.vault)

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def credential(
        self, *, threshold: float = 20.0, polling: dict[str, float] | None = None
    ) -> dict[str, Any]:
        return self.store.create_credential(
            provider="openrouter",
            name="Freebie",
            secret="management-secret",
            threshold=threshold,
            auto_protect=True,
            polling_config=normalize_polling_config(polling),
        )

    def scheduler(self, outcome: dict[str, Any] | Exception | None = None):
        selected = outcome if outcome is not None else {}
        protection = FakeProtection(selected)
        return AdaptiveScheduler(
            self.store, protection, jitter=lambda _low, _high: 0
        ), protection

    def test_default_distance_tiers_accelerate_and_decelerate(self) -> None:
        credential = self.credential()
        scheduler, _ = self.scheduler()
        now = datetime(2026, 10, 6, tzinfo=UTC)

        cases = (
            (0.0, "quiet", 14_400),
            (11.0, "watching", 3_600),
            (16.0, "accelerated", 900),
            (18.5, "critical", 300),
            (19.8, "urgent", 60),
            (8.0, "quiet", 14_400),
        )
        for used, tier, interval in cases:
            with self.subTest(used=used):
                plan = scheduler.plan(credential, snapshot(now, used), [])
                self.assertEqual(tier, plan.tier)
                self.assertEqual(interval, plan.interval_seconds)

    def test_custom_per_credential_tiers_are_validated_and_used(self) -> None:
        custom = normalize_polling_config(
            {
                "quiet_distance": 100,
                "watch_distance": 50,
                "accelerated_distance": 20,
                "critical_distance": 5,
                "quiet_interval_seconds": 7_200,
                "watch_interval_seconds": 1_800,
                "accelerated_interval_seconds": 600,
                "critical_interval_seconds": 120,
                "urgent_interval_seconds": 30,
            }
        )
        credential = self.credential(threshold=200, polling=custom)
        scheduler, _ = self.scheduler()
        plan = scheduler.plan(
            credential, snapshot(datetime(2026, 10, 6, tzinfo=UTC), 130), []
        )

        self.assertEqual("watching", plan.tier)
        self.assertEqual(1_800, plan.interval_seconds)
        with self.assertRaises(PollingConfigError):
            normalize_polling_config({"quiet_distance": 5, "watch_distance": 10})

    def test_burn_velocity_accelerates_before_distance_tier(self) -> None:
        credential = self.credential()
        scheduler, _ = self.scheduler()
        previous_time = datetime(2026, 10, 6, tzinfo=UTC)
        current = snapshot(previous_time + timedelta(hours=1), 8.0)
        history = [
            {**current, "success": 1},
            {**snapshot(previous_time, 0.0), "success": 1},
        ]

        plan = scheduler.plan(credential, current, history)

        self.assertEqual("burn_watching", plan.tier)
        self.assertEqual(3_600, plan.interval_seconds)
        self.assertAlmostEqual(8.0 / 3_600, plan.burn_rate_per_second)
        self.assertAlmostEqual(5_400, plan.estimated_seconds_to_threshold)

    def test_positive_jitter_never_crosses_projected_safety_window(self) -> None:
        credential = self.credential(threshold=25.0)
        previous_time = datetime(2026, 10, 6, tzinfo=UTC)
        elapsed = 932.5
        current_time = previous_time + timedelta(seconds=elapsed)
        current = snapshot(current_time, 5.0)
        history = [
            {**current, "success": 1},
            {**snapshot(previous_time, 0.0), "success": 1},
        ]
        scheduler = AdaptiveScheduler(
            self.store, FakeProtection({}), jitter=lambda _low, high: high
        )

        plan = scheduler.plan(credential, current, history)

        self.assertEqual("burn_watching", plan.tier)
        self.assertLessEqual(plan.interval_seconds, 3_700)
        self.assertEqual(3_700, plan.interval_seconds)

    def test_scheduler_state_survives_restart_and_overdue_work_is_due(self) -> None:
        credential = self.credential()
        scheduler, _ = self.scheduler()
        checked = datetime(2026, 10, 6, tzinfo=UTC)
        current = snapshot(checked, 18.5)
        self.store.record_usage_snapshot(credential["id"], current)
        scheduler.schedule_snapshot(credential["id"], current)
        before = self.store.get_scheduler_state(credential["id"])
        self.assertEqual("critical", before["polling_tier"])
        self.assertEqual(300, before["current_interval_seconds"])

        self.store.close()
        self.store = Store(self.path, self.vault)
        after = self.store.get_scheduler_state(credential["id"])
        self.assertEqual(before, after)
        self.assertEqual(
            [],
            self.store.due_credentials((checked + timedelta(seconds=299)).isoformat()),
        )
        self.assertEqual(
            credential["id"],
            self.store.due_credentials((checked + timedelta(seconds=301)).isoformat())[
                0
            ]["id"],
        )

    def test_provider_failure_never_creates_a_zero_snapshot(self) -> None:
        credential = self.credential()
        scheduler, protection = self.scheduler(
            ProviderError("provider response unavailable")
        )
        scheduler.schedule_now(credential["id"])
        now = datetime.now(UTC) + timedelta(seconds=1)

        self.assertEqual(1, scheduler.run_due_once(now=now))

        self.assertEqual([credential["id"]], protection.calls)
        self.assertEqual([], self.store.usage_history(credential["id"]))
        state = self.store.get_scheduler_state(credential["id"])
        self.assertEqual("error_retry", state["polling_tier"])
        self.assertEqual(1, state["consecutive_failures"])
        self.assertGreater(self.scheduler_time(state["next_check_at"]), now)

    def test_provider_failure_uses_bounded_exponential_backoff(self) -> None:
        credential = self.credential()
        scheduler, _ = self.scheduler(ProviderError("provider unavailable"))
        start = datetime.now(UTC) + timedelta(seconds=1)
        scheduler.schedule_now(credential["id"])

        expected = (60, 120, 240, 480, 900, 900)
        current = start
        for failure_count, delay in enumerate(expected, start=1):
            self.assertEqual(1, scheduler.run_due_once(now=current))
            state = self.store.get_scheduler_state(credential["id"])
            self.assertEqual(failure_count, state["consecutive_failures"])
            actual_delay = (
                self.scheduler_time(state["next_check_at"]) - current
            ).total_seconds()
            self.assertEqual(delay, actual_delay)
            current = self.scheduler_time(state["next_check_at"]) + timedelta(seconds=1)

    def test_vault_runtime_failure_is_retried_without_stopping_other_checks(
        self,
    ) -> None:
        first = self.credential()
        second = self.credential()

        class MixedProtection(FakeProtection):
            def check(
                self, credential_id: str, *, scheduled: bool = False
            ) -> dict[str, Any]:
                self.calls.append(credential_id)
                if credential_id == first["id"]:
                    raise RuntimeError("Secret Service unavailable")
                return {"snapshot": snapshot(datetime.now(UTC), 1.0)}

        protection = MixedProtection({})
        scheduler = AdaptiveScheduler(
            self.store, protection, jitter=lambda _low, _high: 0
        )
        scheduler.schedule_now(first["id"])
        scheduler.schedule_now(second["id"])

        self.assertEqual(2, scheduler.run_due_once(now=datetime.now(UTC)))
        self.assertEqual(
            "error_retry",
            self.store.get_scheduler_state(first["id"])["polling_tier"],
        )
        self.assertEqual(
            "quiet",
            self.store.get_scheduler_state(second["id"])["polling_tier"],
        )

    def test_due_credentials_are_checked_concurrently(self) -> None:
        first = self.credential()
        second = self.credential()
        protection = ConcurrentProtection()
        scheduler = AdaptiveScheduler(
            self.store, protection, jitter=lambda _low, _high: 0
        )
        scheduler.schedule_now(first["id"])
        scheduler.schedule_now(second["id"])

        self.assertEqual(2, scheduler.run_due_once(now=datetime.now(UTC)))
        self.assertEqual(2, protection.max_active)

    def test_runner_wait_tracks_the_next_persisted_deadline(self) -> None:
        credential = self.credential(
            polling=normalize_polling_config(
                {
                    "quiet_interval_seconds": 2,
                    "watch_interval_seconds": 2,
                    "accelerated_interval_seconds": 2,
                    "critical_interval_seconds": 2,
                    "urgent_interval_seconds": 1,
                }
            )
        )
        scheduler, _ = self.scheduler()
        now = datetime.now(UTC)
        self.store.set_scheduler_state(
            credential["id"],
            last_check_at=now.isoformat(),
            next_check_at=(now + timedelta(seconds=1)).isoformat(),
            current_interval_seconds=1,
            polling_tier="urgent",
            consecutive_failures=0,
        )

        self.assertAlmostEqual(
            1.0, scheduler.seconds_until_next_check(now=now), places=2
        )

    def test_paused_and_disabled_credentials_are_not_scheduled(self) -> None:
        paused = self.credential()
        disabled = self.credential()
        self.store.set_paused(paused["id"], True)
        self.store.set_runtime_status(disabled["id"], "disabled")
        scheduler, protection = self.scheduler(
            {"snapshot": snapshot(datetime.now(UTC), 1.0)}
        )

        self.assertEqual(0, scheduler.run_due_once())
        self.assertEqual([], protection.calls)

    def test_queued_check_revalidates_disabled_state_before_provider_call(self) -> None:
        credential = self.credential()
        scheduler, protection = self.scheduler(
            {"snapshot": snapshot(datetime.now(UTC), 1.0)}
        )
        scheduler.schedule_now(credential["id"])
        queued = self.store.due_credentials(
            (datetime.now(UTC) + timedelta(seconds=1)).isoformat()
        )[0]
        self.store.set_runtime_status(credential["id"], "disabled")

        self.assertEqual(0, scheduler._process_credential(queued, datetime.now(UTC)))
        self.assertEqual([], protection.calls)

    @staticmethod
    def scheduler_time(value: str) -> datetime:
        return datetime.fromisoformat(value)


if __name__ == "__main__":
    unittest.main()

