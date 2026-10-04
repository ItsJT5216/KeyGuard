from __future__ import annotations

import os
import secrets
from pathlib import Path


def load_or_create_token(path: Path) -> str:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    try:
        token = path.read_text().strip()
    except FileNotFoundError:
        token = secrets.token_urlsafe(32)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            token = path.read_text().strip()
        else:
            with os.fdopen(descriptor, "w") as handle:
                handle.write(token + "\n")
                handle.flush()
                os.fsync(handle.fileno())
    path.chmod(0o600)
    if len(token) < 32 or any(char.isspace() for char in token):
        raise RuntimeError("KeyGuard authentication token is invalid")
    return token
