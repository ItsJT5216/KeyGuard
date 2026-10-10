from __future__ import annotations

import logging
from collections.abc import Callable
from http.client import HTTPException, InvalidURL
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .store import Store

LOGGER = logging.getLogger("keyguard.notifications")
NTFY_SECRET_ID = "__notification_ntfy_auth__"


class NotificationError(RuntimeError):
    """A sanitized notification failure safe to return through the local API."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        fp: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


def _send_without_redirects(request: Request, timeout: float) -> Any:
    return build_opener(_NoRedirect()).open(request, timeout=timeout)


def validate_notification_config(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("notification configuration must be an object")
    allowed = {"server_url", "topic", "enabled", "auth_token"}
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(f"Unknown notification option: {min(unknown)}")
    result: dict[str, Any] = {}
    if "server_url" in value:
        server_url = value["server_url"]
        if not isinstance(server_url, str):
            raise ValueError("server_url must be text")
        server_url = server_url.strip().rstrip("/")
        parsed = urlparse(server_url)
        try:
            parsed.port
        except ValueError as error:
            raise ValueError(
                "server_url must be an http(s) origin or base path"
            ) from error
        if (
            len(server_url) > 2048
            or parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or any(ord(char) < 33 for char in server_url)
        ):
            raise ValueError("server_url must be an http(s) origin or base path")
        result["server_url"] = server_url
    if "topic" in value:
        topic = value["topic"]
        if (
            not isinstance(topic, str)
            or not topic.strip()
            or len(topic.strip()) > 128
            or any(ord(char) < 33 for char in topic.strip())
            or "/" in topic
        ):
            raise ValueError("topic must be a non-empty single path segment")
        result["topic"] = topic.strip()
    if "enabled" in value:
        if not isinstance(value["enabled"], bool):
            raise ValueError("enabled must be true or false")
        result["enabled"] = value["enabled"]
    if "auth_token" in value:
        token = value["auth_token"]
        if token is not None and (
            not isinstance(token, str)
            or len(token) > 16_384
            or any(ord(char) < 33 or ord(char) > 126 for char in token)
        ):
            raise ValueError("auth_token is invalid")
        result["auth_token"] = token
    return result


class NtfyNotifier:
    def __init__(
        self,
        store: Store,
        *,
        sender: Callable[[Request, float], Any] | None = None,
    ) -> None:
        self.store = store
        self._sender = sender or _send_without_redirects

    def _request(
        self,
        message: str,
        *,
        title: str = "KeyGuard",
        priority: str = "default",
        tags: str = "shield",
    ) -> Request:
        config = self.store.get_notification_delivery_config()
        if not config["enabled"]:
            raise NotificationError("ntfy notifications are disabled")
        topic = quote(config["topic"], safe="")
        headers = {
            "Content-Type": "text/plain; charset=utf-8",
            "Title": title,
            "Priority": priority,
            "Tags": tags,
        }
        token = config["auth_token"]
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return Request(  # noqa: S310 - configured ntfy URL; redirects are rejected
            f"{config['server_url']}/{topic}",
            data=message.encode("utf-8"),
            method="POST",
            headers=headers,
        )

    def send(
        self,
        message: str,
        *,
        title: str = "KeyGuard",
        priority: str = "default",
        tags: str = "shield",
    ) -> None:
        try:
            request = self._request(
                message, title=title, priority=priority, tags=tags
            )
            response = self._sender(request, 10.0)
            try:
                status = getattr(response, "status", 200)
                if status < 200 or status >= 300:
                    raise NotificationError(f"ntfy returned HTTP {status}")
            finally:
                close = getattr(response, "close", None)
                if close is not None:
                    close()
        except HTTPError as exc:
            exc.close()
            raise NotificationError(f"ntfy returned HTTP {exc.code}") from exc
        except (ValueError, InvalidURL, HTTPException) as exc:
            raise NotificationError("ntfy configuration is invalid") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise NotificationError("ntfy is temporarily unavailable") from exc

    def test(self) -> None:
        self.send(
            "KeyGuard notifications are connected.",
            title="KeyGuard test",
            priority="default",
            tags="white_check_mark,shield",
        )

    def deliver_event(
        self,
        credential: dict[str, Any],
        event: dict[str, Any] | None,
        message: str,
        *,
        priority: str,
        tags: str,
    ) -> bool:
        if event is None:
            return False
        try:
            if not self.store.get_notification_config()["enabled"]:
                return False
            self.send(message, priority=priority, tags=tags)
        except (NotificationError, RuntimeError) as exc:
            LOGGER.warning("ntfy delivery failed: %s", exc)
            self.store.record_event(
                credential["id"],
                "notification_delivery",
                "failed",
                {"source_event_id": event["id"], "error": str(exc)},
            )
            return False
        self.store.record_event(
            credential["id"],
            "notification_delivery",
            "success",
            {"source_event_id": event["id"]},
        )
        return True

