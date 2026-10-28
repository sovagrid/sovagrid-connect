# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Place the askpass runtime inside each GUI bundle after PyInstaller builds."""

from __future__ import annotations

from pathlib import Path
import plistlib
import re
import shutil


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
NAME = "SovaGrid-Connect-Askpass"


def stamp_app_version(app: Path) -> None:
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    section = re.search(r"(?ms)^\[project\][ \t]*\r?\n(.*?)(?=^\[|\Z)", project)
    versions = re.findall(r'^version[ \t]*=[ \t]*"([0-9]+\.[0-9]+\.[0-9]+)"[ \t]*$',
                          section.group(1) if section else "", re.MULTILINE)
    if len(versions) != 1:
        raise RuntimeError("macOS packaging needs a numeric major.minor.patch project version")
    path = app / "Contents" / "Info.plist"
    raw = path.read_bytes()
    data = plistlib.loads(raw)
    if not isinstance(data, dict):
        raise RuntimeError("Expected the generated macOS app property dictionary")
    # This happens before the workflow's final ad-hoc signature. Preserve the
    # existing identifier and every other field used by the installed app.
    data["CFBundleShortVersionString"] = versions[0]
    data["CFBundleVersion"] = versions[0]
    fmt = plistlib.FMT_BINARY if raw.startswith(b"bplist00") else plistlib.FMT_XML
    path.write_bytes(plistlib.dumps(data, fmt=fmt, sort_keys=False))


def main() -> None:
    helper = DIST / NAME
    gui_helper = DIST / "SovaGrid-Connect-GUI" / NAME
    if not helper.exists() or gui_helper.exists():
        raise RuntimeError("Expected a fresh Askpass bundle and GUI directory")
    shutil.move(str(helper), str(gui_helper))
    app = DIST / "SovaGrid-Connect-GUI.app"
    if app.exists():
        app_helper = app / "Contents" / "Helpers" / NAME
        app_helper.parent.mkdir(exist_ok=True)
        if gui_helper.is_file():
            shutil.copy2(gui_helper, app_helper)
        else:
            shutil.copytree(gui_helper, app_helper, symlinks=True)
        stamp_app_version(app)


if __name__ == "__main__":
    main()
