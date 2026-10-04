from __future__ import annotations

from typing import Protocol

import keyring

SERVICE_NAME = "io.github.keyguard"


class SecretVault(Protocol):
    def set(self, credential_id: str, secret: str) -> None: ...
    def get(self, credential_id: str) -> str | None: ...
    def delete(self, credential_id: str) -> None: ...


class KeyringVault:
    """Secret storage that refuses plaintext and disabled keyring backends."""

    def __init__(self) -> None:
        backend = keyring.get_keyring()
        backend_name = (
            f"{backend.__class__.__module__}.{backend.__class__.__name__}".lower()
        )
        priority = getattr(backend, "priority", 0)
        if priority <= 0 or "secretservice" not in backend_name:
            raise RuntimeError(
                "KeyGuard requires a secure Secret Service/GNOME Keyring backend; "
                f"refusing {backend_name}"
            )
        self._backend = backend

    def set(self, credential_id: str, secret: str) -> None:
        if not secret:
            raise ValueError("credential secret must not be empty")
        self._backend.set_password(SERVICE_NAME, credential_id, secret)

    def get(self, credential_id: str) -> str | None:
        return self._backend.get_password(SERVICE_NAME, credential_id)

    def delete(self, credential_id: str) -> None:
        try:
            self._backend.delete_password(SERVICE_NAME, credential_id)
        except keyring.errors.PasswordDeleteError:
            pass
