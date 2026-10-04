from __future__ import annotations

import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from keyguard.app import create_app


class MemoryVault:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def set(self, credential_id: str, secret: str) -> None:
        self.values[credential_id] = secret

    def get(self, credential_id: str) -> str | None:
        return self.values.get(credential_id)

    def delete(self, credential_id: str) -> None:
        self.values.pop(credential_id, None)


def client_for(database: Path, vault: MemoryVault) -> TestClient:
    return TestClient(create_app(database_path=database, vault=vault))


def test_credential_survives_app_restart_without_exposing_secret(
    tmp_path: Path,
) -> None:
    database = tmp_path / "keyguard.db"
    vault = MemoryVault()
    secret = "sk-super-secret-1234"

    with client_for(database, vault) as client:
        created = client.post(
            "/api/credentials",
            json={
                "provider": "OpenAI",
                "name": "Primary",
                "secret": secret,
                "threshold": 20,
            },
        )
        assert created.status_code == 201
        body = created.json()
        credential_id = body["id"]
        assert secret not in created.text
        assert body["masked_hint"] == "••••1234"

    with client_for(database, vault) as restarted:
        response = restarted.get(f"/api/credentials/{credential_id}")
        assert response.status_code == 200
        assert response.json()["name"] == "Primary"
        assert secret not in response.text
        assert vault.get(credential_id) == secret

    database_bytes = database.read_bytes()
    assert secret.encode() not in database_bytes
    with sqlite3.connect(database) as connection:
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(credentials)").fetchall()
        }
    assert "secret" not in columns
    assert "api_key" not in columns


def test_pause_resume_history_and_delete(tmp_path: Path) -> None:
    database = tmp_path / "keyguard.db"
    vault = MemoryVault()
    with client_for(database, vault) as client:
        created = client.post(
            "/api/credentials",
            json={"provider": "OpenRouter", "name": "Backup", "secret": "or-key"},
        ).json()
        credential_id = created["id"]

        paused = client.post(f"/api/credentials/{credential_id}/pause")
        assert paused.json()["paused"] is True
        resumed = client.post(f"/api/credentials/{credential_id}/resume")
        assert resumed.json()["paused"] is False

        history = client.get(f"/api/credentials/{credential_id}/history").json()
        assert [event["kind"] for event in history] == [
            "monitoring_resumed",
            "monitoring_paused",
            "credential_added",
        ]

        deleted = client.delete(f"/api/credentials/{credential_id}")
        assert deleted.status_code == 204
        assert vault.get(credential_id) is None
        assert client.get(f"/api/credentials/{credential_id}").status_code == 404


def test_dashboard_and_status_are_served_by_daemon(tmp_path: Path) -> None:
    with client_for(tmp_path / "keyguard.db", MemoryVault()) as client:
        page = client.get("/")
        assert page.status_code == 200
        assert "KeyGuard" in page.text
        status = client.get("/api/status")
        assert status.json() == {
            "status": "ok",
            "credential_count": 0,
            "storage": "sqlite+secret-service",
        }


def test_unknown_credentials_are_404(tmp_path: Path) -> None:
    with client_for(tmp_path / "keyguard.db", MemoryVault()) as client:
        for method, path in [
            ("get", "/api/credentials/missing"),
            ("post", "/api/credentials/missing/check"),
            ("post", "/api/credentials/missing/protect"),
            ("post", "/api/credentials/missing/pause"),
            ("post", "/api/credentials/missing/resume"),
            ("get", "/api/credentials/missing/history"),
            ("delete", "/api/credentials/missing"),
        ]:
            assert getattr(client, method)(path).status_code == 404
