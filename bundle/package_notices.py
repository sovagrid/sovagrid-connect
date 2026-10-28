#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Copy offline third-party notices into every frozen GUI/CLI and ZIP root."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import ssl
import sys
import zlib


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "sovagrid_connect" / "legal" / "third-party"
DIST = ROOT / "dist"


def runtime_inventory() -> dict:
    """Refuse runtime drift rather than shipping notices for a different build."""
    import tkinter
    import PyInstaller
    from sovagrid_connect import __version__

    system = platform.system()
    expected = {
        "Linux": ("3.12.3", "8.6.14", "3.0.13"),
        "Windows": ("3.13.16", "8.6.15", "3.5.9"),
        "Darwin": ("3.13.16", "8.6.18", "3.5.9"),
    }
    if system not in expected:
        raise RuntimeError(f"No audited runtime notices for {system}")
    actual = (platform.python_version(), str(tkinter.Tcl().call("info", "patchlevel")),
              ssl.OPENSSL_VERSION.split()[1])
    if actual != expected[system] or PyInstaller.__version__ != "6.22.3":
        raise RuntimeError(f"Runtime versions need a notice audit: {actual}, PyInstaller {PyInstaller.__version__}")
    if system == "Windows" and zlib.ZLIB_RUNTIME_VERSION != "1.3.1":
        raise RuntimeError(f"Windows zlib version needs a notice audit: {zlib.ZLIB_RUNTIME_VERSION}")
    return {
        "sovagrid_connect": __version__,
        "platform": system, "python": actual[0], "tcl": actual[1],
        "openssl": actual[2], "zlib": zlib.ZLIB_RUNTIME_VERSION,
        "pyinstaller": PyInstaller.__version__,
        "python_executable": sys.executable,
        "static_notices_sha256": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(STATIC.iterdir()) if path.is_file()
        },
    }


def destinations() -> list[Path]:
    result = [
        DIST / "SovaGrid-Connect-CLI" / "_internal" / "sovagrid_connect" / "legal" / "third-party",
        DIST / "SovaGrid-Connect-GUI" / "_internal" / "sovagrid_connect" / "legal" / "third-party",
    ]
    if platform.system() == "Darwin":
        result.append(
            DIST / "SovaGrid-Connect-GUI.app" / "Contents" / "Resources" /
            "sovagrid_connect" / "legal" / "third-party"
        )
    result.append(DIST / "legal" / "third-party")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux-notices", type=Path, help="new exact Ubuntu notice collector output")
    parser.add_argument("--windows-runtime", type=Path, help="Windows runtime provenance manifest")
    args = parser.parse_args()
    system = platform.system()
    if (system == "Linux") != (args.linux_notices is not None):
        parser.error("Linux builds require --linux-notices; other builds must omit it")
    if (system == "Windows") != (args.windows_runtime is not None):
        parser.error("Windows builds require --windows-runtime; other builds must omit it")
    if not (STATIC / "INDEX.md").is_file():
        parser.error("static third-party INDEX.md is missing")
    if args.linux_notices and not (args.linux_notices / "MANIFEST.json").is_file():
        parser.error("Linux native manifest is missing")
    if args.windows_runtime and not args.windows_runtime.is_file():
        parser.error("Windows runtime manifest is missing")
    inventory = runtime_inventory()

    for target in destinations():
        if target != DIST / "legal" / "third-party" and not target.parent.is_dir():
            raise RuntimeError(f"Expected frozen legal resources missing: {target.parent}")
        shutil.copytree(STATIC, target, dirs_exist_ok=True)
        if args.linux_notices:
            shutil.copytree(args.linux_notices, target / "ubuntu", dirs_exist_ok=False)
        if args.windows_runtime:
            shutil.copyfile(args.windows_runtime, target / "windows-runtime.json")
        (target / "runtime.json").write_text(json.dumps(inventory, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"Packaged notices: {target}")


if __name__ == "__main__":
    main()
