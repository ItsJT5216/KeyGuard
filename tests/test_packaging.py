from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from keyguard import api, cli


ROOT = Path(__file__).resolve().parents[1]


class DebianPackagingTests(unittest.TestCase):
    def _build(self, output_directory: Path, umask: int = 0o022) -> Path:
        environment = os.environ.copy()
        environment["SOURCE_DATE_EPOCH"] = "0"
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "packaging" / "build_deb.py"),
                "--output-dir",
                str(output_directory),
            ],
            check=True,
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            preexec_fn=lambda: os.umask(umask),
        )
        return output_directory / "keyguard_0.1.0_all.deb"

    def test_package_is_reproducible_and_contains_the_required_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            first = self._build(base / "first", umask=0o022)
            second = self._build(base / "second", umask=0o077)
            self.assertEqual(
                hashlib.sha256(first.read_bytes()).hexdigest(),
                hashlib.sha256(second.read_bytes()).hexdigest(),
            )

            listing = subprocess.run(
                ["dpkg-deb", "--contents", str(first)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            for installed_path in (
                "./usr/bin/keyguard",
                "./usr/lib/keyguard/keyguard/cli.py",
                "./usr/lib/systemd/user/keyguard.service",
                "./usr/share/applications/keyguard.desktop",
                "./usr/share/keyguard/dashboard/index.html",
                "./usr/share/keyguard/dashboard/app.js",
                "./usr/share/keyguard/dashboard/style.css",
                "./usr/share/doc/keyguard/copyright",
            ):
                self.assertIn(installed_path, listing)
            for line in listing.splitlines():
                if line.endswith("/"):
                    self.assertTrue(line.startswith("drwxr-xr-x"), line)
            wrapper_line = next(
                line for line in listing.splitlines() if line.endswith("./usr/bin/keyguard")
            )
            self.assertTrue(wrapper_line.startswith("-rwxr-xr-x"))

            extracted = base / "extracted"
            subprocess.run(
                ["dpkg-deb", "--extract", str(first), str(extracted)], check=True
            )
            wrapper = (extracted / "usr/bin/keyguard").read_text()
            service = (
                extracted / "usr/lib/systemd/user/keyguard.service"
            ).read_text()
            desktop = (
                extracted / "usr/share/applications/keyguard.desktop"
            ).read_text()
            self.assertIn("PYTHONPATH=/usr/lib/keyguard", wrapper)
            self.assertIn("KEYGUARD_DASHBOARD_DIR=/usr/share/keyguard/dashboard", wrapper)
            self.assertIn("ExecStart=/usr/bin/keyguard serve", service)
            self.assertIn("WantedBy=default.target", service)
            self.assertIn("Exec=/usr/bin/keyguard open", desktop)
            self.assertEqual(
                (ROOT / "src/keyguard/dashboard/index.html").read_bytes(),
                (
                    extracted / "usr/share/keyguard/dashboard/index.html"
                ).read_bytes(),
            )
            installed_content = b"\n".join(
                path.read_bytes()
                for path in sorted(extracted.rglob("*"))
                if path.is_file()
            )
            self.assertNotIn(b"/mnt/data", installed_content)
            self.assertNotIn(str(ROOT).encode(), installed_content)

            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(extracted / "usr/lib/keyguard")
            smoke = subprocess.run(
                [sys.executable, "-m", "keyguard.cli", "--help"],
                check=True,
                capture_output=True,
                text=True,
                env=environment,
            )
            self.assertIn("serve", smoke.stdout)
            self.assertIn("open", smoke.stdout)
            self.assertIn("install", smoke.stdout)
            self.assertIn("uninstall", smoke.stdout)
            self.assertEqual(
                (ROOT / "LICENSE").read_bytes(),
                (extracted / "usr/share/doc/keyguard/copyright").read_bytes(),
            )

            control = subprocess.run(
                ["dpkg-deb", "--field", str(first)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertIn("python3-keyring (>= 24.3.1)", control)
            self.assertIn(
                "Maintainer: Tanner Haywood <jacobthaywood@icloud.com>", control
            )

    def test_system_package_activation_migrates_generated_legacy_unit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            service_dir = Path(temporary)
            service_path = service_dir / "keyguard.service"
            service_path.write_text(
                """[Unit]
Description=KeyGuard API credit protection daemon
After=graphical-session.target
Wants=graphical-session.target

[Service]
Type=simple
ExecStart="/home/tanner/.local/share/keyguard/venv/bin/python" -m keyguard.cli serve
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
UMask=0077

[Install]
WantedBy=default.target
"""
            )
            with (
                patch.dict(
                    os.environ,
                    {"KEYGUARD_EXECUTABLE": "/usr/bin/keyguard"},
                    clear=False,
                ),
                patch.object(cli, "load_or_create_token"),
                patch.object(cli, "systemd_user_dir", return_value=service_dir),
                patch.object(cli, "_systemctl", return_value="/usr/bin/systemctl"),
                patch.object(cli.subprocess, "run") as run,
            ):
                cli.install()

            self.assertFalse(service_path.exists())
            self.assertEqual(3, run.call_count)
            self.assertIn("reenable", run.call_args_list[1].args[0])
            self.assertIn("restart", run.call_args_list[2].args[0])

    def test_system_package_activation_preserves_custom_user_unit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            service_dir = Path(temporary)
            service_path = service_dir / "keyguard.service"
            service_path.write_text("[Service]\\nExecStart=/custom/keyguard\\n")
            with (
                patch.dict(
                    os.environ,
                    {"KEYGUARD_EXECUTABLE": "/usr/bin/keyguard"},
                    clear=False,
                ),
                patch.object(cli, "load_or_create_token"),
                patch.object(cli, "systemd_user_dir", return_value=service_dir),
                patch.object(cli, "_systemctl", return_value="/usr/bin/systemctl"),
                patch.object(cli.subprocess, "run") as run,
                self.assertRaisesRegex(SystemExit, "Custom user unit"),
            ):
                cli.install()

            self.assertEqual(
                "[Service]\\nExecStart=/custom/keyguard\\n", service_path.read_text()
            )
            run.assert_not_called()

    def test_uninstall_stops_service_without_deleting_user_state(self) -> None:
        with (
            patch.object(cli, "_systemctl", return_value="/usr/bin/systemctl"),
            patch.object(cli.subprocess, "run") as run,
            patch.object(cli, "database_path") as database,
            patch.object(cli, "auth_token_path") as auth_token,
        ):
            cli.uninstall()

        self.assertEqual(
            [
                [
                    "/usr/bin/systemctl",
                    "--user",
                    "disable",
                    "--now",
                    "keyguard.service",
                ],
                ["/usr/bin/systemctl", "--user", "daemon-reload"],
            ],
            [call.args[0] for call in run.call_args_list],
        )
        database.assert_not_called()
        auth_token.assert_not_called()

    def test_packaged_dashboard_directory_is_authoritative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "index.html").write_text("packaged dashboard")
            with patch.dict(
                os.environ, {"KEYGUARD_DASHBOARD_DIR": str(directory)}, clear=False
            ):
                resource = api._dashboard_resource("index.html")
                self.assertEqual(b"packaged dashboard", resource.read_bytes())

    def test_package_has_no_removal_script_for_user_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = self._build(Path(temporary) / "output")
            control = Path(temporary) / "control"
            subprocess.run(
                ["dpkg-deb", "--control", str(package), str(control)], check=True
            )
            self.assertFalse((control / "postrm").exists())
            self.assertFalse((control / "prerm").exists())


if __name__ == "__main__":
    unittest.main()

