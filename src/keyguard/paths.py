from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> Path:
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    path = base / "keyguard"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def database_path() -> Path:
    return data_dir() / "keyguard.db"


def auth_token_path() -> Path:
    return data_dir() / "api-token"


def runtime_port_path() -> Path:
    return data_dir() / "daemon-port"


def systemd_user_dir() -> Path:
    return (
        Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
        / "systemd"
        / "user"
    )


def applications_dir() -> Path:
    return (
        Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        / "applications"
    )
