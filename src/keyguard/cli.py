from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

from .api import create_server
from .auth import load_or_create_token, mint_bootstrap
from .paths import (
    applications_dir,
    auth_token_path,
    database_path,
    runtime_port_path,
    systemd_user_dir,
)
from .store import Store
from .vault import KeyringVault


def _read_port() -> int | None:
    try:
        value = int(runtime_port_path().read_text().strip())
    except (FileNotFoundError, ValueError):
        return None
    return value if 1024 <= value <= 65535 else None


def _write_port(port: int) -> None:
    path = runtime_port_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(16)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w") as handle:
            handle.write(f"{port}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def serve() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    store = Store(database_path(), KeyringVault())
    token = load_or_create_token(auth_token_path())
    preferred_port = _read_port() or 0
    try:
        server = create_server(store, token, preferred_port)
    except OSError:
        if not preferred_port:
            raise
        server = create_server(store, token, 0)
    _write_port(server.server_port)
    logging.getLogger("keyguard").info(
        "KeyGuard listening on 127.0.0.1:%s", server.server_port
    )
    server.scheduler_runner.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.scheduler_runner.stop()
        server.scheduler_runner.join(timeout=2)
        server.server_close()
        store.close()


def _challenge(port: int, token: str) -> bool:
    nonce = secrets.token_hex(32)
    url = f"http://127.0.0.1:{port}/api/challenge?nonce={nonce}"
    expected = hmac.new(token.encode(), nonce.encode(), hashlib.sha256).hexdigest()
    request = urllib.request.Request(url)
    with urllib.request.urlopen(request, timeout=0.5) as response:  # noqa: S310
        payload = json.loads(response.read())
    proof = payload.get("proof") if isinstance(payload, dict) else None
    return isinstance(proof, str) and hmac.compare_digest(proof, expected)


def _wait_for_daemon(token: str) -> int:
    for _ in range(40):
        try:
            port = _read_port()
            if port is not None and _challenge(port, token):
                return port
        except (OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(0.1)
    raise SystemExit("KeyGuard daemon did not become ready")


def _systemctl() -> str:
    executable = shutil.which("systemctl")
    if executable is None:
        raise SystemExit("systemctl is required to manage the KeyGuard user service")
    return executable


def open_dashboard() -> None:
    token = load_or_create_token(auth_token_path())
    subprocess.run(  # noqa: S603 - systemctl is resolved to an absolute path
        [_systemctl(), "--user", "start", "keyguard.service"], check=True
    )
    port = _wait_for_daemon(token)
    bootstrap = mint_bootstrap(token)
    fragment = urllib.parse.quote(bootstrap, safe="")
    webbrowser.open(f"http://127.0.0.1:{port}/#token={fragment}", new=2)


def _systemd_quote(path: str) -> str:
    escaped = path.replace("\\", "\\\\").replace('"', '\\"')
    escaped = escaped.replace("%", "%%").replace("$", "$$")
    return f'"{escaped}"'


def _desktop_quote(path: str) -> str:
    escaped = path.replace("\\", "\\\\").replace('"', '\\"')
    escaped = escaped.replace("%", "%%").replace("$", "\\$")
    return f'"{escaped}"'


def install() -> None:
    python = os.path.abspath(sys.executable)
    load_or_create_token(auth_token_path())
    service_dir = systemd_user_dir()
    app_dir = applications_dir()
    service_dir.mkdir(parents=True, exist_ok=True)
    app_dir.mkdir(parents=True, exist_ok=True)

    service = f"""[Unit]
Description=KeyGuard API credit protection daemon
After=graphical-session.target
Wants=graphical-session.target

[Service]
Type=simple
ExecStart={_systemd_quote(python)} -m keyguard.cli serve
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
UMask=0077

[Install]
WantedBy=default.target
"""
    desktop = f"""[Desktop Entry]
Type=Application
Name=KeyGuard
Comment=Open the KeyGuard API credit dashboard
Exec={_desktop_quote(python)} -m keyguard.cli open
Terminal=false
Categories=Utility;Security;
StartupNotify=true
"""
    service_path = service_dir / "keyguard.service"
    desktop_path = app_dir / "dev.tanner.KeyGuard.desktop"
    service_path.write_text(service)
    desktop_path.write_text(desktop)
    service_path.chmod(0o600)
    desktop_path.chmod(0o644)
    systemctl = _systemctl()
    subprocess.run(  # noqa: S603 - systemctl is resolved to an absolute path
        [systemctl, "--user", "daemon-reload"], check=True
    )
    subprocess.run(  # noqa: S603 - systemctl is resolved to an absolute path
        [systemctl, "--user", "enable", "keyguard.service"], check=True
    )
    subprocess.run(  # noqa: S603 - systemctl is resolved to an absolute path
        [systemctl, "--user", "restart", "keyguard.service"], check=True
    )
    print(f"Installed {service_path}")
    print(f"Installed {desktop_path}")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="keyguard")
    sub = result.add_subparsers(dest="command", required=True)
    sub.add_parser("serve", help="run the loopback daemon")
    sub.add_parser("open", help="start the daemon and open the dashboard")
    sub.add_parser("install", help="install and enable the user service")
    return result


def main() -> None:
    args = parser().parse_args()
    if args.command == "serve":
        serve()
    elif args.command == "open":
        open_dashboard()
    elif args.command == "install":
        install()


if __name__ == "__main__":
    main()
