from __future__ import annotations

import pytest

import keyguard.vault as vault_module


class PlaintextBackend:
    priority = 1


class DisabledBackend:
    priority = 0


class SecureSecretServiceBackend:
    priority = 5


SecureSecretServiceBackend.__module__ = "keyring.backends.SecretService"


@pytest.mark.parametrize("backend", [PlaintextBackend(), DisabledBackend()])
def test_insecure_keyring_backend_is_refused(monkeypatch, backend) -> None:
    monkeypatch.setattr(vault_module.keyring, "get_keyring", lambda: backend)
    with pytest.raises(RuntimeError, match="requires a secure"):
        vault_module.KeyringVault()


def test_secret_service_backend_is_accepted(monkeypatch) -> None:
    backend = SecureSecretServiceBackend()
    monkeypatch.setattr(vault_module.keyring, "get_keyring", lambda: backend)
    vault = vault_module.KeyringVault()
    assert vault._backend is backend
