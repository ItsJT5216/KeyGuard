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
    def _build(self, output_directory: Path) -> Path:
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
        )
        return output_directory / "keyguard_0.1.0_all.deb"

    def test_package_is_reproducible_and_contains_the_required_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            first = self._build(base / "first")
            second = self._build(base / "second")
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
            ):
                self.assertIn(installed_path, listing)
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

    def test_system_package_activation_uses_packaged_units_without_user_overrides(self) -> None:
        with (
            patch.dict(
                os.environ, {"KEYGUARD_EXECUTABLE": "/usr/bin/keyguard"}, clear=False
            ),
            patch.object(cli, "load_or_create_token"),
            patch.object(cli, "systemd_user_dir") as service_dir,
            patch.object(cli, "applications_dir") as applications_dir,
            patch.object(cli, "_systemctl", return_value="/usr/bin/systemctl"),
            patch.object(cli.subprocess, "run") as run,
        ):
            cli.install()

        service_dir.assert_not_called()
        applications_dir.assert_not_called()
        self.assertEqual(3, run.call_count)
        self.assertIn("enable", run.call_args_list[1].args[0])
        self.assertIn("restart", run.call_args_list[2].args[0])

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
