from __future__ import annotations

import argparse
import shutil
import subprocess
import webbrowser
from pathlib import Path

import uvicorn

from .app import create_app

HOST = "127.0.0.1"
PORT = 8765


def install_service() -> None:
    executable = shutil.which("keyguard")
    if executable is None:
        raise SystemExit("keyguard executable was not found on PATH")
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    unit_path = unit_dir / "keyguard.service"
    unit_path.write_text(
        f"""[Unit]
Description=KeyGuard local credential monitor
After=graphical-session.target

[Service]
Type=simple
ExecStart={executable} serve
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
""",
        encoding="utf-8",
    )
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
    subprocess.run(
        ["systemctl", "--user", "enable", "--now", "keyguard.service"], check=True
    )
    print(f"Installed and started {unit_path}")


def open_dashboard() -> None:
    subprocess.run(["systemctl", "--user", "start", "keyguard.service"], check=True)
    webbrowser.open(f"http://{HOST}:{PORT}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="keyguard")
    subcommands = parser.add_subparsers(dest="command", required=True)
    serve = subcommands.add_parser("serve", help="run the localhost daemon")
    serve.add_argument("--host", default=HOST, choices=[HOST])
    serve.add_argument("--port", default=PORT, type=int)
    subcommands.add_parser("open", help="open the existing daemon dashboard")
    subcommands.add_parser(
        "install-service", help="install and start the systemd user service"
    )
    args = parser.parse_args()

    if args.command == "serve":
        uvicorn.run(create_app(), host=args.host, port=args.port)
    elif args.command == "open":
        open_dashboard()
    elif args.command == "install-service":
        install_service()


if __name__ == "__main__":
    main()
