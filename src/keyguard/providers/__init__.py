from __future__ import annotations

from typing import Any

from .base import ProviderAdapter, ProviderError
from .openrouter import OpenRouterAdapter


class ProviderRegistry:
    def __init__(self, adapters: list[ProviderAdapter] | None = None) -> None:
        selected = adapters if adapters is not None else [OpenRouterAdapter()]
        self._adapters = {adapter.provider_id: adapter for adapter in selected}

    @staticmethod
    def normalize(provider: str) -> str:
        return provider.strip().lower().replace(" ", "")

    def get(self, provider: str) -> ProviderAdapter:
        provider_id = self.normalize(provider)
        try:
            return self._adapters[provider_id]
        except KeyError as error:
            raise ProviderError(f"Provider {provider} is not implemented") from error

    def validate_configuration(
        self, provider: str, metadata: dict[str, Any], action: str
    ) -> tuple[str, dict[str, Any], str]:
        provider_id = self.normalize(provider)
        adapter = self._adapters.get(provider_id)
        if adapter is None:
            if metadata or action != "notify_only":
                raise ProviderError(f"Provider {provider} is not implemented")
            return provider, {}, "notify_only"
        normalized = adapter.validate_metadata(metadata)
        if action not in (*adapter.actions, "notify_only"):
            raise ProviderError(
                f"{provider_id} does not support protection action {action}"
            )
        return provider_id, normalized, action

    def describe(self, provider: str) -> dict[str, Any]:
        adapter = self.get(provider)
        return {
            "id": adapter.provider_id,
            "capabilities": sorted(adapter.capabilities),
            "actions": list(adapter.actions),
        }

    def list(self) -> list[dict[str, Any]]:
        return [self.describe(provider_id) for provider_id in sorted(self._adapters)]

    def enrich(self, credential: dict[str, Any]) -> dict[str, Any]:
        result = dict(credential)
        adapter = self._adapters.get(self.normalize(credential["provider"]))
        result["capabilities"] = sorted(adapter.capabilities) if adapter else []
        result["available_actions"] = list(adapter.actions) if adapter else []
        return result

