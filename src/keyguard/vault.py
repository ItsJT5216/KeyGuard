from __future__ import annotations

from typing import Protocol

SERVICE_NAME = "dev.tanner.KeyGuard"


class Vault(Protocol):
    def set(self, credential_id: str, secret: str) -> None: ...
    def get(self, credential_id: str) -> str | None: ...
    def delete(self, credential_id: str) -> None: ...


class KeyringVault:
    """Fail-closed Secret Service adapter. There is deliberately no file fallback."""

    def __init__(self) -> None:
        try:
            import keyring
            from keyring.errors import KeyringError, PasswordDeleteError
        except ImportError as exc:
            raise RuntimeError("KeyGuard requires the 'keyring' package") from exc
        self._keyring = keyring
        self._keyring_error = KeyringError
        self._password_delete_error = PasswordDeleteError

    @staticmethod
    def _username(credential_id: str) -> str:
        return f"credential:{credential_id}"

    def set(self, credential_id: str, secret: str) -> None:
        try:
            self._keyring.set_password(
                SERVICE_NAME, self._username(credential_id), secret
            )
        except self._keyring_error as exc:
            raise RuntimeError("Secret Service rejected the credential") from exc

    def get(self, credential_id: str) -> str | None:
        try:
            return self._keyring.get_password(
                SERVICE_NAME, self._username(credential_id)
            )
        except self._keyring_error as exc:
            raise RuntimeError("Secret Service could not read the credential") from exc

    def delete(self, credential_id: str) -> None:
        try:
            self._keyring.delete_password(SERVICE_NAME, self._username(credential_id))
        except self._password_delete_error:
            return
        except self._keyring_error as exc:
            raise RuntimeError(
                "Secret Service could not delete the credential"
            ) from exc
