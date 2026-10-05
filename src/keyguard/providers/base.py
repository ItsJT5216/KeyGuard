from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

CAN_FETCH_USAGE = "CAN_FETCH_USAGE"
CAN_FETCH_BALANCE = "CAN_FETCH_BALANCE"
CAN_DISABLE_KEY = "CAN_DISABLE_KEY"
CAN_DELETE_KEY = "CAN_DELETE_KEY"
CAN_SET_LIMIT = "CAN_SET_LIMIT"
CAN_IDENTIFY_INDIVIDUAL_KEY_USAGE = "CAN_IDENTIFY_INDIVIDUAL_KEY_USAGE"


class ProviderError(RuntimeError):
    """A sanitized provider failure safe to return through the local API."""


@dataclass(frozen=True)
class UsageSnapshot:
    checked_at: str
    used: float
    limit: float | None
    remaining: float | None
    unit: str
    provider_status: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "checked_at": self.checked_at,
            "used": self.used,
            "limit": self.limit,
            "remaining": self.remaining,
            "unit": self.unit,
            "provider_status": self.provider_status,
        }


class ProviderAdapter(Protocol):
    provider_id: str
    capabilities: frozenset[str]
    actions: tuple[str, ...]

    def validate_metadata(self, metadata: dict[str, Any]) -> dict[str, Any]: ...

    def fetch_usage(self, secret: str, metadata: dict[str, Any]) -> UsageSnapshot: ...

    def execute_action(
        self, action: str, secret: str, metadata: dict[str, Any]
    ) -> dict[str, Any]: ...
