# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Run the packaged entry points without opening a network connection or GUI."""

from __future__ import annotations

import platform
import plistlib
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
SUFFIX = ".exe" if platform.system() == "Windows" else ""


def check(executable: Path, *args: str, expect_text: str | None = None) -> None:
    if not executable.is_file():
        raise FileNotFoundError(executable)
    result = subprocess.run(
        [str(executable), *args],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{executable.name} {' '.join(args)} exited {result.returncode}: "
            f"{result.stdout}\n{result.stderr}"
        )
    # A Windows --windowed executable has no attached stdout. Its zero exit
    # status still proves its packaged argument parser reached --help.
    if expect_text and expect_text not in result.stdout:
        raise RuntimeError(f"{executable.name} did not print {expect_text!r}")
    print(f"PASS {executable.name} {' '.join(args)}", flush=True)


def main() -> None:
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    version = re.search(r'^version = "([^"]+)"$', project, re.MULTILINE)
    if version is None:
        raise RuntimeError("Repository version is missing")
    cli = DIST / "SovaGrid-Connect-CLI" / f"SovaGrid-Connect-CLI{SUFFIX}"
    gui = DIST / "SovaGrid-Connect-GUI" / f"SovaGrid-Connect-GUI{SUFFIX}"
    helper_root = DIST / "SovaGrid-Connect-GUI" / "SovaGrid-Connect-Askpass"
    askpass = helper_root if platform.system() == "Darwin" else helper_root / f"SovaGrid-Connect-Askpass{SUFFIX}"
    check(cli, "--help", expect_text="connect")
    check(cli, "--version", expect_text=f"SovaGrid Connect {version.group(1)}")
    check(cli, "connect", "--help", expect_text="--jump-host")
    check(cli, "license", expect_text="GNU AFFERO GENERAL PUBLIC LICENSE")
    check(cli, "license", "--attribution", expect_text="Jigokuraku01")
    check(cli, "third-party-licenses", expect_text="CPython 3.13.16")
    check(cli, "third-party-licenses", "--list", expect_text="PyInstaller-6.22.3-COPYING.txt")
    check(cli, "third-party-licenses", "runtime.json", expect_text='"static_notices_sha256"')
    if platform.system() == "Linux":
        check(cli, "third-party-licenses", "ubuntu/MANIFEST.json", expect_text='"packages"')
        assert (DIST / "legal" / "third-party" / "ubuntu" / "MANIFEST.json").is_file()
    elif platform.system() == "Windows":
        check(cli, "third-party-licenses", "windows-runtime.json", expect_text="VCRUNTIME140.dll")
        assert (DIST / "legal" / "third-party" / "windows-runtime.json").is_file()
    assert (DIST / "legal" / "third-party" / "CPython-3.13.16-LICENSE").is_file()
    check(gui, "--help")
    check(gui, "--legal-self-test")
    check(askpass, "--self-test", expect_text="SovaGrid askpass pipe OK")
    if platform.system() == "Darwin":
        info = plistlib.loads((DIST / "SovaGrid-Connect-GUI.app" / "Contents" / "Info.plist").read_bytes())
        for key in ("CFBundleShortVersionString", "CFBundleVersion"):
            assert info.get(key) == version.group(1), f"macOS app {key} does not match project version"
        app = DIST / "SovaGrid-Connect-GUI.app" / "Contents" / "MacOS" / "SovaGrid-Connect-GUI"
        check(app, "--help")
        check(app, "--legal-self-test")
        app_helper = DIST / "SovaGrid-Connect-GUI.app" / "Contents" / "Helpers" / "SovaGrid-Connect-Askpass"
        check(app_helper, "--self-test", expect_text="SovaGrid askpass pipe OK")


if __name__ == "__main__":
    main()
