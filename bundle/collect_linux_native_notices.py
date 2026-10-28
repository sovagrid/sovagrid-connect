#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Collect exact Ubuntu package notices for native libraries PyInstaller bundled.

Run on the same Linux CI host immediately after PyInstaller's build and before
creating the release archive. This script only reads the build host and writes
to --output. It fails closed if a bundled library cannot be matched to an
installed, dpkg-owned library by hash or GNU ELF build ID. PyInstaller may
rewrite RPATH, in which case hashes differ but the build ID remains the same.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


LIBRARY_RE = re.compile(r"^lib[^/]+\.so(?:\.[0-9.]+)?$")
COMMON_LICENSE_RE = re.compile(r"/usr/share/common-licenses/([A-Za-z0-9.+_-]+)")
LDCONFIG_RE = re.compile(r"^\s*(\S+)\s+\(([^)]+)\)\s+=>\s+(\S+)")


def referenced_common_licenses(text: str) -> set[str]:
    # Debian copyright prose may finish a sentence with e.g. ".../GPL-2.".
    # Preserve version dots (LGPL-2.1), but omit sentence-ending full stops.
    return {name.rstrip(".") for name in COMMON_LICENSE_RE.findall(text)}


def run(*args: str) -> str:
    result = subprocess.run(args, check=True, text=True, capture_output=True)
    return result.stdout.strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def elf_build_id(path: Path) -> str | None:
    try:
        notes = run("readelf", "-n", str(path))
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    match = re.search(r"Build ID:\s*([0-9a-fA-F]+)", notes)
    return match.group(1).lower() if match else None


def ldconfig_index() -> dict[str, list[Path]]:
    index: dict[str, list[Path]] = defaultdict(list)
    for line in run("ldconfig", "-p").splitlines():
        match = LDCONFIG_RE.match(line)
        if match:
            name, abi, location = match.groups()
            if "x86-64" in abi or "AArch64" in abi or "aarch64" in abi:
                index[name].append(Path(location))
    return index


def bundled_libraries(dist: Path) -> dict[str, list[Path]]:
    by_name: dict[str, list[Path]] = defaultdict(list)
    for path in dist.rglob("lib*.so*"):
        if path.is_file() and LIBRARY_RE.fullmatch(path.name):
            by_name[path.name].append(path)
    return dict(sorted(by_name.items()))


def resolve_library(name: str, bundled: list[Path], index: dict[str, list[Path]]) -> tuple[Path, str]:
    bundled_hashes = {sha256(path) for path in bundled}
    if len(bundled_hashes) != 1:
        raise RuntimeError(f"{name}: copies in the bundle have different hashes")
    bundled_id = elf_build_id(bundled[0])
    def match(candidates: list[Path]) -> tuple[Path, str] | None:
        for candidate in candidates:
            resolved = candidate.resolve()
            if not resolved.is_file():
                continue
            if sha256(resolved) in bundled_hashes:
                return resolved, "sha256"
            if bundled_id and elf_build_id(resolved) == bundled_id:
                return resolved, "elf_build_id"
        return None

    found = match(index.get(name, []))
    if found:
        return found
    # Some packages (for example BLT) live outside ldconfig's indexed dirs.
    for root in (Path("/usr/lib"), Path("/lib")):
        if root.is_dir():
            found = match(list(root.rglob(name)))
            if found:
                return found
    raise RuntimeError(f"{name}: no matching installed library (hash or ELF build ID)")


def owning_package(path: Path) -> str:
    # dpkg records the regular path under /usr/lib on merged-usr systems.
    for candidate in (path, Path(str(path).replace("/usr/lib/", "/lib/", 1))):
        try:
            output = run("dpkg-query", "-S", str(candidate))
        except subprocess.CalledProcessError:
            continue
        first = output.splitlines()[0]
        package, delimiter, _ = first.partition(": ")
        if delimiter and package:
            return package
    raise RuntimeError(f"{path}: no dpkg owner")


def package_version(package: str) -> str:
    return run("dpkg-query", "-W", "-f=${Version}", package)


def copy_binary(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", required=True, type=Path, help="built dist/ directory")
    parser.add_argument("--output", required=True, type=Path, help="new third-party notices directory")
    parser.add_argument("--python-license", type=Path, help="CPython source LICENSE from exact pinned version")
    parser.add_argument("--python-doc-license", type=Path, help="CPython Doc/license.rst from exact pinned version")
    parser.add_argument("--tcl-license", type=Path, help="Tcl license.terms from exact pinned version")
    parser.add_argument("--tk-license", type=Path, help="Tk license.terms from exact pinned version")
    parser.add_argument("--pyinstaller-license", type=Path, help="PyInstaller COPYING.txt from exact pinned version")
    arguments = parser.parse_args()

    if not sys.platform.startswith("linux"):
        parser.error("run this collector on the Linux build host")
    dist = arguments.dist.resolve(strict=True)
    output = arguments.output.resolve()
    if output == dist or dist in output.parents:
        parser.error("output must be outside dist so notices cannot change the library inventory")
    if output.exists():
        parser.error(f"output already exists: {output}")

    library_paths = bundled_libraries(dist)
    if not library_paths:
        parser.error(f"no shared libraries found in {dist}")

    index = ldconfig_index()
    packages: dict[str, dict] = {}
    problems = []
    for name, copies in library_paths.items():
        try:
            original, match_method = resolve_library(name, copies, index)
            package = owning_package(original)
            version = package_version(package)
            item = packages.setdefault(package, {"version": version, "libraries": []})
            item["libraries"].append({
                "name": name,
                "bundle_sha256": sha256(copies[0]),
                "host_sha256": sha256(original),
                "match_method": match_method,
                "elf_build_id": elf_build_id(original),
                "host_path": str(original),
                "bundle_copies": [str(path.relative_to(dist)) for path in copies],
            })
        except (RuntimeError, subprocess.CalledProcessError) as error:
            problems.append(str(error))

    if problems:
        for problem in problems:
            print(f"ERROR: {problem}", file=sys.stderr)
        return 1

    output.mkdir(parents=True)
    common_licenses: set[str] = set()
    for package, item in sorted(packages.items()):
        directory = package.split(":", 1)[0]
        source = Path("/usr/share/doc") / directory / "copyright"
        if not source.is_file():
            print(f"ERROR: missing distro copyright: {source}", file=sys.stderr)
            return 1
        destination = output / directory / "copyright"
        copy_binary(source, destination)
        item["copyright"] = str(destination.relative_to(output))
        item["copyright_sha256"] = sha256(destination)
        common_licenses.update(referenced_common_licenses(source.read_text(errors="replace")))

    for name in sorted(common_licenses):
        source = Path("/usr/share/common-licenses") / name
        if not source.is_file():
            print(f"ERROR: missing referenced common license: {source}", file=sys.stderr)
            return 1
        copy_binary(source, output / "common-licenses" / name)

    supplied = {}
    for key, option in {
        "CPython-LICENSE": arguments.python_license,
        "CPython-Doc-license.rst": arguments.python_doc_license,
        "Tcl-license.terms": arguments.tcl_license,
        "Tk-license.terms": arguments.tk_license,
        "PyInstaller-COPYING.txt": arguments.pyinstaller_license,
    }.items():
        if option is None:
            continue
        if not option.is_file():
            parser.error(f"not a file: {option}")
        destination = output / "upstream" / key
        copy_binary(option, destination)
        supplied[key] = {"path": str(destination.relative_to(output)), "sha256": sha256(destination)}

    manifest = {
        "purpose": "Exact notices for native libraries bundled by PyInstaller on the Linux build host",
        "packages": dict(sorted(packages.items())),
        "common_licenses": sorted(common_licenses),
        "upstream_licenses": supplied,
    }
    (output / "MANIFEST.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    print(f"Collected {len(library_paths)} shared libraries from {len(packages)} Ubuntu packages into {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
