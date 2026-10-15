from __future__ import annotations

import json
import math
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from .base import (
    CAN_DELETE_KEY,
    CAN_DISABLE_KEY,
    CAN_FETCH_BALANCE,
    CAN_FETCH_USAGE,
    CAN_IDENTIFY_INDIVIDUAL_KEY_USAGE,
    CAN_SET_LIMIT,
    BalanceSnapshot,
    ProviderError,
    UsageSnapshot,
)

BASE_URL = "https://openrouter.ai/api/v1"


class Transport(Protocol):
    def request(
        self,
        method: str,
        path: str,
        token: str,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        pass


class _RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep the management credential on the configured provider origin."""

    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


class OpenRouterTransport:
    def __init__(self, opener: urllib.request.OpenerDirector | None = None) -> None:
        self._opener = opener or urllib.request.build_opener(_RejectRedirectHandler())

    def request(
        self,
        method: str,
        path: str,
        token: str,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        encoded = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(  # noqa: S310 - fixed HTTPS provider base
            f"{BASE_URL}{path}",
            data=encoded,
            method=method,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "KeyGuard/0.1",
            },
        )
        try:
            with self._opener.open(request, timeout=20) as response:
                payload = json.loads(response.read())
        except urllib.error.HTTPError as error:
            error.close()
            raise ProviderError(f"OpenRouter returned HTTP {error.code}") from error
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ProviderError("OpenRouter response was unavailable") from error
        if not isinstance(payload, dict):
            raise ProviderError("OpenRouter returned a malformed response")
        return payload


def _number(
    data: dict[str, Any], field: str, *, optional: bool = False
) -> float | None:
    value = data.get(field)
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProviderError(f"OpenRouter response is missing valid {field}")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise ProviderError(f"OpenRouter response contains invalid {field}")
    return number


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _billing_period(
    data: dict[str, Any], field: str
) -> tuple[str | None, str | None, str | None]:
    value = data.get(field)
    if value is None:
        return None, None, None
    if not isinstance(value, str) or value not in {"daily", "weekly", "monthly"}:
        raise ProviderError(f"OpenRouter response contains invalid {field}")

    start = _utc_now().replace(hour=0, minute=0, second=0, microsecond=0)
    if value == "daily":
        end = start + timedelta(days=1)
    elif value == "weekly":
        start -= timedelta(days=start.weekday())
        end = start + timedelta(days=7)
    else:
        start = start.replace(day=1)
        if start.month == 12:
            end = start.replace(year=start.year + 1, month=1)
        else:
            end = start.replace(month=start.month + 1)
    return start.isoformat(), end.isoformat(), value


def _timestamp(data: dict[str, Any], field: str) -> str | None:
    value = data.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ProviderError(f"OpenRouter response contains invalid {field}")
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError("timestamp is missing a UTC offset")
        return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError) as error:
        raise ProviderError(
            f"OpenRouter response contains invalid {field}"
        ) from error


class OpenRouterAdapter:
    provider_id = "openrouter"
    capabilities = frozenset(
        {
            CAN_FETCH_USAGE,
            CAN_FETCH_BALANCE,
            CAN_DISABLE_KEY,
            CAN_DELETE_KEY,
            CAN_SET_LIMIT,
            CAN_IDENTIFY_INDIVIDUAL_KEY_USAGE,
        }
    )
    actions = ("disable",)

    def __init__(self, transport: Transport | None = None) -> None:
        self.transport = transport or OpenRouterTransport()

    def validate_metadata(self, metadata: dict[str, Any]) -> dict[str, Any]:
        key_hash = metadata.get("key_hash")
        if (
            not isinstance(key_hash, str)
            or len(key_hash) != 64
            or any(character not in "0123456789abcdefABCDEF" for character in key_hash)
        ):
            raise ProviderError("OpenRouter requires a 64-character API key hash")
        return {"key_hash": key_hash.lower()}

    def _key_path(self, metadata: dict[str, Any]) -> str:
        key_hash = self.validate_metadata(metadata)["key_hash"]
        return f"/keys/{urllib.parse.quote(key_hash, safe='')}"

    def _key_data(self, payload: dict[str, Any]) -> dict[str, Any]:
        data = payload.get("data")
        if not isinstance(data, dict):
            raise ProviderError("OpenRouter returned a malformed key response")
        return data

    def fetch_usage(self, secret: str, metadata: dict[str, Any]) -> UsageSnapshot:
        data = self._key_data(
            self.transport.request("GET", self._key_path(metadata), secret)
        )
        used = _number(data, "usage")
        limit = _number(data, "limit", optional=True)
        remaining = _number(data, "limit_remaining", optional=True)
        period_start, period_end, limit_reset = _billing_period(
            data, "limit_reset"
        )
        expires_at = _timestamp(data, "expires_at")
        if remaining is None and limit is not None:
            remaining = max(limit - used, 0.0)
        return UsageSnapshot(
            checked_at=datetime.now(UTC).isoformat(),
            used=used,
            limit=limit,
            remaining=remaining,
            unit="USD",
            period_start=period_start,
            period_end=period_end,
            expires_at=expires_at,
            provider_status={
                "disabled": bool(data.get("disabled", False)),
                "limit_reset": limit_reset,
                "scope": "individual_key",
            },
        )

    def fetch_balance(
        self, secret: str, metadata: dict[str, Any]
    ) -> BalanceSnapshot:
        del metadata
        payload = self.transport.request("GET", "/credits", secret)
        data = payload.get("data")
        if not isinstance(data, dict):
            raise ProviderError("OpenRouter returned a malformed credits response")
        total_credits = _number(data, "total_credits")
        total_usage = _number(data, "total_usage")
        return BalanceSnapshot(
            available=max(total_credits - total_usage, 0.0),
            unit="USD",
        )

    def execute_action(
        self, action: str, secret: str, metadata: dict[str, Any]
    ) -> dict[str, Any]:
        if action != "disable":
            raise ProviderError(f"OpenRouter does not support action {action}")
        path = self._key_path(metadata)
        self.transport.request("PATCH", path, secret, {"disabled": True})
        verified = self._key_data(self.transport.request("GET", path, secret))
        if verified.get("disabled") is not True:
            raise ProviderError("OpenRouter did not verify the key as disabled")
        return {"action": "disable", "verified": True}

