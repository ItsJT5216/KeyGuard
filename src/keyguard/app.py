from pathlib import Path
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from .storage import SQLiteStore
from .vault import KeyringVault, SecretVault


class CredentialCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=120)
    secret: str = Field(min_length=1)
    threshold: float | None = Field(default=None, ge=0)


class CredentialUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str | None = Field(default=None, min_length=1, max_length=80)
    name: str | None = Field(default=None, min_length=1, max_length=120)
    threshold: float | None = Field(default=None, ge=0)
    auto_protect: bool | None = None


def create_app(
    *,
    database_path: Path | None = None,
    vault: SecretVault | None = None,
    dashboard_path: Path | None = None,
) -> FastAPI:
    if database_path is None:
        database_path = Path.home() / ".local" / "share" / "keyguard" / "keyguard.db"
    store = SQLiteStore(database_path)
    active_vault = vault or KeyringVault()

    app = FastAPI(title="KeyGuard", version="0.1.0")
    app.state.store = store
    app.state.vault = active_vault

    def get_store() -> SQLiteStore:
        return app.state.store

    def get_vault() -> SecretVault:
        return app.state.vault

    def credential_or_404(store: SQLiteStore, credential_id: str) -> dict:
        try:
            return store.get_credential(credential_id)
        except KeyError as error:
            raise HTTPException(
                status_code=404, detail="credential not found"
            ) from error

    @app.get("/api/status")
    def api_status(store: SQLiteStore = Depends(get_store)) -> dict:
        return {
            "status": "ok",
            "credential_count": len(store.list_credentials()),
            "storage": "sqlite+secret-service",
        }

    @app.get("/api/credentials")
    def list_credentials(store: SQLiteStore = Depends(get_store)) -> list[dict]:
        return store.list_credentials()

    @app.post("/api/credentials", status_code=status.HTTP_201_CREATED)
    def create_credential(
        payload: CredentialCreate,
        store: SQLiteStore = Depends(get_store),
        secret_vault: SecretVault = Depends(get_vault),
    ) -> dict:
        credential_id = str(uuid4())
        masked_hint = (
            f"••••{payload.secret[-4:]}" if len(payload.secret) >= 4 else "••••"
        )
        secret_vault.set(credential_id, payload.secret)
        try:
            credential = store.create_credential(
                credential_id=credential_id,
                provider=payload.provider,
                name=payload.name,
                masked_hint=masked_hint,
                threshold=payload.threshold,
            )
            store.record_event(
                credential_id, "credential_added", {"provider": payload.provider}
            )
        except Exception:
            secret_vault.delete(credential_id)
            raise
        return credential

    @app.get("/api/credentials/{credential_id}")
    def get_credential(
        credential_id: str, store: SQLiteStore = Depends(get_store)
    ) -> dict:
        return credential_or_404(store, credential_id)

    @app.patch("/api/credentials/{credential_id}")
    def update_credential(
        credential_id: str,
        payload: CredentialUpdate,
        store: SQLiteStore = Depends(get_store),
    ) -> dict:
        credential_or_404(store, credential_id)
        values = payload.model_dump(exclude_unset=True)
        return store.update_credential(credential_id, values)

    @app.delete(
        "/api/credentials/{credential_id}", status_code=status.HTTP_204_NO_CONTENT
    )
    def delete_credential(
        credential_id: str,
        store: SQLiteStore = Depends(get_store),
        secret_vault: SecretVault = Depends(get_vault),
    ) -> Response:
        credential_or_404(store, credential_id)
        secret_vault.delete(credential_id)
        store.delete_credential(credential_id)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.post("/api/credentials/{credential_id}/check")
    def check_credential(
        credential_id: str, store: SQLiteStore = Depends(get_store)
    ) -> dict:
        credential_or_404(store, credential_id)
        event = store.record_event(
            credential_id,
            "check_requested",
            {"result": "provider_adapter_required"},
        )
        return {"status": "queued", "event": event}

    @app.post("/api/credentials/{credential_id}/protect")
    def protect_credential(
        credential_id: str, store: SQLiteStore = Depends(get_store)
    ) -> dict:
        credential_or_404(store, credential_id)
        event = store.record_event(
            credential_id,
            "protection_requested",
            {"result": "provider_adapter_required"},
        )
        return {"status": "action_unavailable", "event": event}

    @app.post("/api/credentials/{credential_id}/pause")
    def pause_credential(
        credential_id: str, store: SQLiteStore = Depends(get_store)
    ) -> dict:
        credential_or_404(store, credential_id)
        store.record_event(credential_id, "monitoring_paused", {})
        return store.update_credential(
            credential_id, {"paused": True, "status": "paused"}
        )

    @app.post("/api/credentials/{credential_id}/resume")
    def resume_credential(
        credential_id: str, store: SQLiteStore = Depends(get_store)
    ) -> dict:
        credential_or_404(store, credential_id)
        store.record_event(credential_id, "monitoring_resumed", {})
        return store.update_credential(
            credential_id, {"paused": False, "status": "healthy"}
        )

    @app.get("/api/credentials/{credential_id}/history")
    def credential_history(
        credential_id: str, store: SQLiteStore = Depends(get_store)
    ) -> list[dict]:
        try:
            return store.history(credential_id)
        except KeyError as error:
            raise HTTPException(
                status_code=404, detail="credential not found"
            ) from error

    @app.post("/api/notifications/test")
    def test_notification() -> dict:
        return {"status": "not_configured"}

    @app.get("/api/providers")
    def list_providers() -> list[dict]:
        return []

    static_path = dashboard_path or Path(__file__).with_name("dashboard")
    app.mount("/", StaticFiles(directory=static_path, html=True), name="dashboard")
    return app
