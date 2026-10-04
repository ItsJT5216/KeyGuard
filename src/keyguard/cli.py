from __future__ import annotations

import argparse
import logging
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

from .api import create_server
from .paths import applications_dir, database_path, systemd_user_dir
from .store import Store
from .vault import KeyringVault

DEFAULT_PORT = 17832


def _port() -> int:
    value = int(os.environ.get("KEYGUARD_PORT", DEFAULT_PORT))
    if not 1024 <= value <= 65535:
        raise SystemExit("KEYGUARD_PORT must be between 1024 and 65535")
    return value


def serve() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    store = Store(database_path(), KeyringVault())
    server = create_server(store, _port())
    logging.getLogger("keyguard").info(
        "KeyGuard listening on 127.0.0.1:%s", server.server_port
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        store.close()


def _wait_for_daemon(port: int) -> None:
    url = f"http://127.0.0.1:{port}/api/status"
    for _ in range(40):
        try:
            with urllib.request.urlopen(url, timeout=0.5) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    raise SystemExit("KeyGuard daemon did not become ready")


def _systemctl() -> str:
    executable = shutil.which("systemctl")
    if executable is None:
        raise SystemExit("systemctl is required to manage the KeyGuard user service")
    return executable


def open_dashboard() -> None:
    port = _port()
    subprocess.run(  # noqa: S603 - systemctl is resolved to an absolute path
        [_systemctl(), "--user", "start", "keyguard.service"], check=True
    )
    _wait_for_daemon(port)
    webbrowser.open(f"http://127.0.0.1:{port}/", new=2)


def install() -> None:
    python = Path(sys.executable).resolve()
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
ExecStart={python} -m keyguard.cli serve
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
Exec={python} -m keyguard.cli open
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
        [systemctl, "--user", "enable", "--now", "keyguard.service"], check=True
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
