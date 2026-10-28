# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Local legal documents are bundled with installed and frozen clients."""

from importlib.resources import files

ATTRIBUTION = "SovaGrid — Copyright (C) 2026 Jigokuraku01"
SOURCE_URL = "https://github.com/sovagrid/sovagrid-connect"


def document(name: str) -> str:
    if name not in {"LICENSE", "ATTRIBUTION.md", "NOTICE"}:
        raise ValueError("Unknown legal document")
    return files("sovagrid_connect").joinpath("legal").joinpath(name).read_text(encoding="utf-8")


def third_party_documents() -> tuple[str, ...]:
    """List the notices shipped with this installation, including CI additions."""
    root = files("sovagrid_connect").joinpath("legal", "third-party")
    result: list[str] = []

    def visit(directory, prefix: str = "") -> None:
        for entry in directory.iterdir():
            name = f"{prefix}{entry.name}"
            if entry.is_dir():
                visit(entry, f"{name}/")
            elif entry.is_file():
                result.append(name)

    visit(root)
    return tuple(sorted(result, key=lambda name: (name != "INDEX.md", name.casefold())))


def third_party_document(name: str) -> str:
    """Read only a bundled notice selected from the resource inventory."""
    if name not in third_party_documents():
        raise ValueError("Unknown third-party legal document")
    return files("sovagrid_connect").joinpath("legal", "third-party", *name.split("/")).read_text(
        encoding="utf-8"
    )
