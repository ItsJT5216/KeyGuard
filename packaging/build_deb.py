#!/usr/bin/env python3
"""Build KeyGuard's reproducible, source-only Debian package."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import subprocess
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _copy_file(source: Path, destination: Path, mode: int = 0o644) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def _normalize_tree(root: Path, timestamp: int) -> None:
    paths = [root, *sorted(root.rglob("*"))]
    for path in paths:
        if path.is_dir():
            path.chmod(0o755)
    for path in reversed(paths):
        os.utime(path, (timestamp, timestamp), follow_symlinks=False)


def _stage(package_root: Path, version: str, timestamp: int) -> None:
    source_package = ROOT / "src" / "keyguard"
    library_package = package_root / "usr" / "lib" / "keyguard" / "keyguard"
    for source in sorted(source_package.rglob("*")):
        if not source.is_file() or "__pycache__" in source.parts or source.suffix == ".pyc":
            continue
        relative = source.relative_to(source_package)
        if relative.parts[0] == "dashboard" and source.name != "__init__.py":
            continue
        _copy_file(source, library_package / relative)

    dashboard = package_root / "usr" / "share" / "keyguard" / "dashboard"
    for name in ("index.html", "app.js", "style.css"):
        _copy_file(source_package / "dashboard" / name, dashboard / name)

    wrapper = package_root / "usr" / "bin" / "keyguard"
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    wrapper.write_text(
        "#!/bin/sh\n"
        "export PYTHONPATH=/usr/lib/keyguard\n"
        "export KEYGUARD_EXECUTABLE=/usr/bin/keyguard\n"
        "export KEYGUARD_DASHBOARD_DIR=/usr/share/keyguard/dashboard\n"
        'exec /usr/bin/python3 -m keyguard.cli "$@"\n'
    )
    wrapper.chmod(0o755)

    _copy_file(
        ROOT / "packaging" / "keyguard.service",
        package_root / "usr" / "lib" / "systemd" / "user" / "keyguard.service",
    )
    _copy_file(
        ROOT / "packaging" / "keyguard.desktop",
        package_root / "usr" / "share" / "applications" / "keyguard.desktop",
    )
    _copy_file(
        ROOT / "LICENSE",
        package_root / "usr" / "share" / "doc" / "keyguard" / "copyright",
    )

    control = package_root / "DEBIAN" / "control"
    control.parent.mkdir(parents=True, exist_ok=True)
    control.write_text(
        "Package: keyguard\n"
        f"Version: {version}\n"
        "Section: utils\n"
        "Priority: optional\n"
        "Architecture: all\n"
        "Depends: python3 (>= 3.11), python3-keyring (>= 24.3.1)\n"
        "Maintainer: Tanner Haywood <jacobthaywood@icloud.com>\n"
        "Description: Local-first API credit protection daemon\n"
        " KeyGuard monitors provider usage from a loopback-only daemon and protects\n"
        " configured credentials when their thresholds are crossed.\n"
    )
    control.chmod(0o644)
    _normalize_tree(package_root, timestamp)


def build(output_directory: Path) -> Path:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text())
    version = metadata["project"]["version"]
    timestamp = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    if timestamp < 0:
        raise SystemExit("SOURCE_DATE_EPOCH must be non-negative")
    output_directory.mkdir(parents=True, exist_ok=True)
    output = output_directory / f"keyguard_{version}_all.deb"
    dpkg_deb = shutil.which("dpkg-deb")
    if dpkg_deb is None:
        raise SystemExit("dpkg-deb is required to build the Debian package")

    with tempfile.TemporaryDirectory(prefix="keyguard-deb-") as temporary:
        package_root = Path(temporary) / "root"
        package_root.mkdir()
        _stage(package_root, version, timestamp)
        environment = os.environ.copy()
        environment["SOURCE_DATE_EPOCH"] = str(timestamp)
        subprocess.run(  # noqa: S603 - dpkg-deb is resolved to an absolute path
            [
                dpkg_deb,
                "--root-owner-group",
                "--build",
                "--uniform-compression",
                "-Zxz",
                str(package_root),
                str(output),
            ],
            check=True,
            env=environment,
        )
    output.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    print(build(args.output_dir))


if __name__ == "__main__":
    main()

