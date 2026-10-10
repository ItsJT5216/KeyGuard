from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
import time
from pathlib import Path

BOOTSTRAP_TTL_SECONDS = 30
SESSION_TTL_SECONDS = 8 * 60 * 60
MAX_USED_BOOTSTRAPS = 64
MAX_SESSIONS = 32


def _read_valid_token(path: Path) -> str:
    token = path.read_text().strip()
    if len(token) < 32 or any(char.isspace() for char in token):
        raise RuntimeError("KeyGuard authentication token is invalid")
    return token


def load_or_create_token(path: Path) -> str:
    """Create an owner-only token without ever publishing a partial file."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    try:
        token = _read_valid_token(path)
    except FileNotFoundError:
        candidate = secrets.token_urlsafe(32)
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(16)}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "w") as handle:
                handle.write(candidate + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                pass
            token = _read_valid_token(path)
        finally:
            temporary.unlink(missing_ok=True)
    path.chmod(0o600)
    return token


def mint_bootstrap(owner_token: str, *, issued_at: int | None = None) -> str:
    timestamp = int(time.time()) if issued_at is None else issued_at
    payload = f"{timestamp}.{secrets.token_urlsafe(32)}"
    signature = hmac.new(
        owner_token.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()
    return f"{payload}.{signature}"


class SessionAuthority:
    """Validates one-use bootstraps and manages origin-scoped browser sessions."""

    def __init__(self, owner_token: str) -> None:
        self._owner_token = owner_token
        self._used_bootstraps: dict[str, float] = {}
        self._sessions: dict[str, float] = {}
        self._lock = threading.Lock()

    def challenge(self, nonce: str) -> str:
        return hmac.new(
            self._owner_token.encode(), nonce.encode(), hashlib.sha256
        ).hexdigest()

    def exchange_bootstrap(self, candidate: str) -> str | None:
        try:
            timestamp_text, nonce, signature = candidate.split(".", 2)
            timestamp = int(timestamp_text)
        except (AttributeError, ValueError):
            return None
        wall_now = time.time()
        if timestamp > wall_now + 5 or wall_now - timestamp > BOOTSTRAP_TTL_SECONDS:
            return None
        payload = f"{timestamp_text}.{nonce}"
        expected = hmac.new(
            self._owner_token.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()
        if not nonce or not hmac.compare_digest(signature, expected):
            return None

        monotonic_now = time.monotonic()
        with self._lock:
            self._prune(monotonic_now, wall_now)
            if signature in self._used_bootstraps:
                return None
            if len(self._used_bootstraps) >= MAX_USED_BOOTSTRAPS:
                oldest = min(self._used_bootstraps, key=self._used_bootstraps.get)
                self._used_bootstraps.pop(oldest)
            self._used_bootstraps[signature] = timestamp + BOOTSTRAP_TTL_SECONDS
            token = secrets.token_urlsafe(32)
            if len(self._sessions) >= MAX_SESSIONS:
                oldest = min(self._sessions, key=self._sessions.get)
                self._sessions.pop(oldest)
            self._sessions[token] = monotonic_now + SESSION_TTL_SECONDS
            return token

    def verify_session(self, candidate: str) -> bool:
        monotonic_now = time.monotonic()
        with self._lock:
            self._prune(monotonic_now, time.time())
            expiry = self._sessions.get(candidate)
            return expiry is not None and expiry >= monotonic_now

    def _prune(self, monotonic_now: float, wall_now: float) -> None:
        self._used_bootstraps = {
            token: expiry
            for token, expiry in self._used_bootstraps.items()
            if expiry >= wall_now
        }
        self._sessions = {
            token: expiry
            for token, expiry in self._sessions.items()
            if expiry >= monotonic_now
        }

