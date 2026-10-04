from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from typing import Any
from urllib.parse import urlparse

from .store import Store

LOGGER = logging.getLogger("keyguard")
MAX_BODY_BYTES = 64 * 1024
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _text(value: Any, field: str, *, maximum: int = 120) -> str:
    if not isinstance(value, str):
        raise ApiError(422, "VALIDATION_ERROR", f"{field} must be text")
    value = value.strip()
    if not value or len(value) > maximum or any(ord(char) < 32 for char in value):
        raise ApiError(422, "VALIDATION_ERROR", f"{field} is invalid")
    return value


def _threshold(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ApiError(
            422, "VALIDATION_ERROR", "threshold must be a non-negative number"
        )
    result = float(value)
    if result < 0 or result > 1_000_000_000:
        raise ApiError(
            422, "VALIDATION_ERROR", "threshold must be a non-negative number"
        )
    return result


def _boolean(value: Any, field: str, default: bool = False) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ApiError(422, "VALIDATION_ERROR", f"{field} must be true or false")
    return value


def make_handler(store: Store):
    class Handler(BaseHTTPRequestHandler):
        server_version = "KeyGuard"
        sys_version = ""

        def log_message(self, format_string: str, *args: object) -> None:
            LOGGER.info("%s - %s", self.client_address[0], format_string % args)

        def _security_headers(self, *, api: bool = False) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; connect-src 'self'; script-src 'self'; "
                "style-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
            )
            if api:
                self.send_header("Cache-Control", "no-store")

        def _json(self, status: int, payload: Any) -> None:
            body = json.dumps(
                payload, separators=(",", ":"), ensure_ascii=False
            ).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self._security_headers(api=True)
            self.end_headers()
            self.wfile.write(body)

        def _empty(self, status: int = 204) -> None:
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self._security_headers(api=True)
            self.end_headers()

        def _error(self, error: ApiError) -> None:
            self._json(
                error.status, {"error": {"code": error.code, "message": error.message}}
            )

        def _require_local_origin(self) -> None:
            origin = self.headers.get("Origin")
            if not origin:
                return
            parsed = urlparse(origin)
            if parsed.scheme not in {"http", "https"} or parsed.hostname not in {
                "127.0.0.1",
                "localhost",
                "::1",
            }:
                raise ApiError(403, "ORIGIN_REJECTED", "Request origin is not local")

        def _body(self) -> dict[str, Any]:
            self._require_local_origin()
            if self.headers.get_content_type() != "application/json":
                raise ApiError(
                    415, "JSON_REQUIRED", "Content-Type must be application/json"
                )
            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                raise ApiError(411, "LENGTH_REQUIRED", "Content-Length is required")
            try:
                length = int(raw_length)
            except ValueError as exc:
                raise ApiError(400, "INVALID_LENGTH", "Invalid Content-Length") from exc
            if length <= 0 or length > MAX_BODY_BYTES:
                raise ApiError(413, "BODY_TOO_LARGE", "Request body size is invalid")
            try:
                payload = json.loads(self.rfile.read(length))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ApiError(
                    400, "INVALID_JSON", "Request body is not valid JSON"
                ) from exc
            if not isinstance(payload, dict):
                raise ApiError(
                    422, "VALIDATION_ERROR", "Request body must be an object"
                )
            return payload

        @staticmethod
        def _segments(path: str) -> list[str]:
            return [part for part in urlparse(path).path.split("/") if part]

        def do_GET(self) -> None:
            try:
                path = urlparse(self.path).path
                if path in STATIC_FILES:
                    resource_name, content_type = STATIC_FILES[path]
                    resource = files("keyguard.dashboard").joinpath(resource_name)
                    body = resource.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(body)))
                    self._security_headers()
                    self.end_headers()
                    self.wfile.write(body)
                    return
                segments = self._segments(self.path)
                if segments == ["api", "status"]:
                    self._json(200, {"status": "ok", "service": "keyguard"})
                elif segments == ["api", "credentials"]:
                    self._json(200, {"credentials": store.list_credentials()})
                elif segments == ["api", "providers"]:
                    self._json(200, {"providers": store.providers()})
                elif len(segments) == 3 and segments[:2] == ["api", "credentials"]:
                    credential = store.get_credential(segments[2])
                    if credential is None:
                        raise ApiError(404, "NOT_FOUND", "Credential not found")
                    self._json(200, {"credential": credential})
                elif (
                    len(segments) == 4
                    and segments[:2] == ["api", "credentials"]
                    and segments[3] == "history"
                ):
                    history = store.history(segments[2])
                    if history is None:
                        raise ApiError(404, "NOT_FOUND", "Credential not found")
                    self._json(200, {"events": history})
                else:
                    raise ApiError(404, "NOT_FOUND", "Route not found")
            except ApiError as error:
                self._error(error)
            except Exception:
                LOGGER.exception("Unhandled GET failure")
                self._error(ApiError(500, "INTERNAL_ERROR", "Request failed"))

        def do_POST(self) -> None:
            try:
                segments = self._segments(self.path)
                body = self._body()
                if segments == ["api", "credentials"]:
                    allowed = {
                        "provider",
                        "name",
                        "api_key",
                        "threshold",
                        "auto_protect",
                    }
                    if set(body) - allowed:
                        raise ApiError(
                            422, "VALIDATION_ERROR", "Unknown credential field"
                        )
                    secret = _text(body.get("api_key"), "api_key", maximum=16_384)
                    credential = store.create_credential(
                        provider=_text(body.get("provider"), "provider", maximum=80),
                        name=_text(body.get("name"), "name"),
                        secret=secret,
                        threshold=_threshold(body.get("threshold")),
                        auto_protect=_boolean(body.get("auto_protect"), "auto_protect"),
                    )
                    self._json(201, {"credential": credential})
                    return
                if len(segments) == 4 and segments[:2] == ["api", "credentials"]:
                    credential_id, action = segments[2], segments[3]
                    if action in {"pause", "resume"}:
                        result = store.set_paused(credential_id, action == "pause")
                        if result is None:
                            raise ApiError(404, "NOT_FOUND", "Credential not found")
                        self._json(200, {"credential": result})
                        return
                    if action == "check":
                        event = store.record_event(
                            credential_id,
                            "check_requested",
                            "pending_provider_integration",
                            {"message": "Provider checks are implemented by X-7"},
                        )
                        if event is None:
                            raise ApiError(404, "NOT_FOUND", "Credential not found")
                        self._json(202, {"event": event})
                        return
                    if action == "protect":
                        event = store.record_event(
                            credential_id,
                            "protection_requested",
                            "provider_not_configured",
                            {"message": "Protection actions are implemented by X-7"},
                        )
                        if event is None:
                            raise ApiError(404, "NOT_FOUND", "Credential not found")
                        self._json(
                            409,
                            {
                                "event": event,
                                "error": {"code": "PROVIDER_NOT_CONFIGURED"},
                            },
                        )
                        return
                if segments == ["api", "notifications", "test"]:
                    raise ApiError(
                        501, "NOT_IMPLEMENTED", "Notifications are implemented by X-9"
                    )
                raise ApiError(404, "NOT_FOUND", "Route not found")
            except ApiError as error:
                self._error(error)
            except RuntimeError as error:
                LOGGER.warning("Credential operation failed: %s", error)
                self._error(
                    ApiError(
                        503, "SECRET_SERVICE_UNAVAILABLE", "Secret Service unavailable"
                    )
                )
            except Exception:
                LOGGER.exception("Unhandled POST failure")
                self._error(ApiError(500, "INTERNAL_ERROR", "Request failed"))

        def do_PATCH(self) -> None:
            try:
                segments = self._segments(self.path)
                if len(segments) != 3 or segments[:2] != ["api", "credentials"]:
                    raise ApiError(404, "NOT_FOUND", "Route not found")
                body = self._body()
                allowed = {"provider", "name", "api_key", "threshold", "auto_protect"}
                if not body or set(body) - allowed:
                    raise ApiError(422, "VALIDATION_ERROR", "Invalid credential fields")
                values: dict[str, Any] = {}
                if "provider" in body:
                    values["provider"] = _text(body["provider"], "provider", maximum=80)
                if "name" in body:
                    values["name"] = _text(body["name"], "name")
                if "api_key" in body:
                    values["api_key"] = _text(
                        body["api_key"], "api_key", maximum=16_384
                    )
                if "threshold" in body:
                    values["threshold"] = _threshold(body["threshold"])
                if "auto_protect" in body:
                    values["auto_protect"] = _boolean(
                        body["auto_protect"], "auto_protect"
                    )
                credential = store.update_credential(segments[2], values)
                if credential is None:
                    raise ApiError(404, "NOT_FOUND", "Credential not found")
                self._json(200, {"credential": credential})
            except ApiError as error:
                self._error(error)
            except RuntimeError:
                self._error(
                    ApiError(
                        503, "SECRET_SERVICE_UNAVAILABLE", "Secret Service unavailable"
                    )
                )
            except Exception:
                LOGGER.exception("Unhandled PATCH failure")
                self._error(ApiError(500, "INTERNAL_ERROR", "Request failed"))

        def do_DELETE(self) -> None:
            try:
                self._require_local_origin()
                segments = self._segments(self.path)
                if len(segments) != 3 or segments[:2] != ["api", "credentials"]:
                    raise ApiError(404, "NOT_FOUND", "Route not found")
                if not store.delete_credential(segments[2]):
                    raise ApiError(404, "NOT_FOUND", "Credential not found")
                self._empty()
            except ApiError as error:
                self._error(error)
            except RuntimeError:
                self._error(
                    ApiError(
                        503, "SECRET_SERVICE_UNAVAILABLE", "Secret Service unavailable"
                    )
                )
            except Exception:
                LOGGER.exception("Unhandled DELETE failure")
                self._error(ApiError(500, "INTERNAL_ERROR", "Request failed"))

    return Handler


def create_server(store: Store, port: int = 17832) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), make_handler(store))
