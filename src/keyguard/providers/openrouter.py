from __future__ import annotations

import json
import math
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from typing import Any, Protocol

from .base import (
    CAN_DELETE_KEY,
    CAN_DISABLE_KEY,
    CAN_FETCH_BALANCE,
    CAN_FETCH_USAGE,
    CAN_IDENTIFY_INDIVIDUAL_KEY_USAGE,
    CAN_SET_LIMIT,
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
        if remaining is None and limit is not None:
            remaining = max(limit - used, 0.0)
        return UsageSnapshot(
            checked_at=datetime.now(UTC).isoformat(),
            used=used,
            limit=limit,
            remaining=remaining,
            unit="USD",
            provider_status={
                "disabled": bool(data.get("disabled", False)),
                "limit_reset": data.get("limit_reset"),
                "scope": "individual_key",
            },
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
