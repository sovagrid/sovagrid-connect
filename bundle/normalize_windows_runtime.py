#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Use a documented VC redistributable DLL and Windows 10+ system UCRT."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
MANIFEST = ROOT / "build" / "windows-runtime.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def visual_studio_roots() -> list[Path]:
    program_files = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
    vswhere = program_files / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    roots: list[Path] = []
    if vswhere.is_file():
        result = subprocess.run(
            [str(vswhere), "-products", "*", "-property", "installationPath"],
            capture_output=True, text=True, check=True,
        )
        roots.extend(Path(line.strip()) for line in result.stdout.splitlines() if line.strip())
    # The hosted runner can provide multiple side-by-side Visual Studio builds.
    for base in (Path(os.environ.get("ProgramFiles", r"C:\Program Files")), program_files):
        roots.extend((base / "Microsoft Visual Studio").glob("20??/*"))
    return list(dict.fromkeys(root for root in roots if root.is_dir()))


def version_key(path: Path) -> tuple[int, ...]:
    # .../MSVC/<version>/x64/Microsoft.VC*.CRT/vcruntime140.dll
    version = path.parents[2].name
    return tuple(int(part) for part in version.split(".") if part.isdigit())


def redist_vcruntime() -> Path:
    candidates = []
    for root in visual_studio_roots():
        candidates.extend((root / "VC" / "Redist" / "MSVC").glob(
            "*/x64/Microsoft.VC*.CRT/VCRUNTIME140.dll"
        ))
    candidates = [path for path in candidates if path.is_file() and "debug_nonredist" not in str(path).lower()]
    if not candidates:
        raise RuntimeError("VCRUNTIME140.dll not found under the licensed Visual Studio VC/Redist/MSVC tree")
    return max(candidates, key=version_key).resolve()


def main() -> None:
    if platform.system() != "Windows":
        raise RuntimeError("Windows runtime normalization must run on the Windows CI host")
    source = redist_vcruntime()
    source_hash = sha256(source)
    removed = []
    installed = []
    for directory in sorted(DIST.rglob("_internal")):
        if not directory.is_dir():
            continue
        for file in directory.iterdir():
            if not file.is_file() or file.suffix.lower() != ".dll":
                continue
            name = file.name.lower()
            if name == "ucrtbase.dll" or name.startswith("api-ms-win-"):
                removed.append(str(file.relative_to(DIST)))
                file.unlink()
            elif name == "vcruntime140.dll":
                shutil.copyfile(source, file)
                if sha256(file) != source_hash:
                    raise RuntimeError(f"VC redistributable copy changed: {file}")
                installed.append(str(file.relative_to(DIST)))
    if len(installed) < 3 or not removed:
        raise RuntimeError(f"Expected three bundled runtimes and local UCRT copies, found {len(installed)} / {len(removed)}")
    record = {
        "minimum_windows": "Windows 10",
        "vc_runtime": {
            "name": "VCRUNTIME140.dll",
            "source": str(source),
            "vc_redist_version": source.parents[2].name,
            "sha256": source_hash,
            "destinations": installed,
            "license_terms": "https://learn.microsoft.com/cpp/windows/redistributing-visual-cpp-files",
            "redist_list": "https://learn.microsoft.com/en-us/visualstudio/releases/2022/redistribution",
        },
        "system_ucrt": {
            "removed_app_local_dlls": removed,
            "reason": "Windows 10+ provides UCRT as a serviced operating-system component",
            "source": "https://learn.microsoft.com/en-us/cpp/porting/upgrade-your-code-to-the-universal-crt",
        },
    }
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Recorded Microsoft runtime provenance in {MANIFEST}; removed {len(removed)} UCRT/API-set DLL copies")


if __name__ == "__main__":
    main()
