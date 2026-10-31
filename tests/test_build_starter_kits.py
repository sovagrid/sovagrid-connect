# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Starter archives must use the same static SHA-256 as the GUI downloader."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tools.build_starter_kits import approved_release_pins
from sovagrid_connect.server_bundle_download import PUBLISHED_SERVER_SOURCE_SHA256


HASH = "a" * 64
OTHER = "b" * 64
IMPORT = "from .server_bundle_download import PUBLISHED_SERVER_SOURCE_SHA256, downloaded_server_bundle\n"
PINS = (
    f'_APPROVED_PROMOTION_BUNDLE_SHA256 = "{HASH}"\n'
    f'_APPROVED_HUB_ONLY_UPDATE_BUNDLE_SHA256 = "{HASH}"\n'
    f'_APPROVED_LOCAL_OPERATIONS_MANIFEST_SHA256 = "{OTHER}"\n'
)


class StarterPinTests(unittest.TestCase):
    def fixture(self, gui: str, downloader: str | None = None) -> tuple[TemporaryDirectory, Path]:
        temporary = TemporaryDirectory(prefix="sg-starter-pins-")
        package = Path(temporary.name) / "sovagrid_connect"
        package.mkdir()
        (package / "gui.py").write_text(gui, encoding="utf-8")
        (package / "server_bundle_download.py").write_text(
            downloader or f'PUBLISHED_SERVER_SOURCE_SHA256 = "{HASH}"\n', encoding="utf-8")
        return temporary, Path(temporary.name)

    def test_current_gui_uses_downloader_literal(self) -> None:
        pins = approved_release_pins()
        self.assertEqual(pins["_APPROVED_SERVER_SOURCE_SHA256"],
                         PUBLISHED_SERVER_SOURCE_SHA256)

    def test_exact_imported_alias_resolves_without_running_gui(self) -> None:
        gui = IMPORT + "_APPROVED_SERVER_SOURCE_SHA256 = PUBLISHED_SERVER_SOURCE_SHA256\n" + PINS
        temporary, root = self.fixture(gui)
        with temporary:
            pins = approved_release_pins(source_root=root)
        self.assertEqual(pins["_APPROVED_SERVER_SOURCE_SHA256"], HASH)
        self.assertEqual(pins["_APPROVED_LOCAL_OPERATIONS_MANIFEST_SHA256"], OTHER)

    def test_untrusted_binding_and_expression_are_rejected(self) -> None:
        cases = (
            "from .other import PUBLISHED_SERVER_SOURCE_SHA256\n"
            "_APPROVED_SERVER_SOURCE_SHA256 = PUBLISHED_SERVER_SOURCE_SHA256\n" + PINS,
            IMPORT + f'PUBLISHED_SERVER_SOURCE_SHA256 = "{OTHER}"\n'
            "_APPROVED_SERVER_SOURCE_SHA256 = PUBLISHED_SERVER_SOURCE_SHA256\n" + PINS,
            IMPORT + f'(PUBLISHED_SERVER_SOURCE_SHA256 := "{OTHER}")\n'
            "_APPROVED_SERVER_SOURCE_SHA256 = PUBLISHED_SERVER_SOURCE_SHA256\n" + PINS,
            IMPORT + "_APPROVED_SERVER_SOURCE_SHA256 = PUBLISHED_SERVER_SOURCE_SHA256 + ''\n" + PINS,
            "def unused():\n    from .server_bundle_download import PUBLISHED_SERVER_SOURCE_SHA256\n"
            "_APPROVED_SERVER_SOURCE_SHA256 = PUBLISHED_SERVER_SOURCE_SHA256\n" + PINS,
        )
        for gui in cases:
            with self.subTest(gui=gui.splitlines()[0]):
                temporary, root = self.fixture(gui)
                with temporary, self.assertRaises(RuntimeError):
                    approved_release_pins(source_root=root)

    def test_computed_or_duplicate_downloader_pin_is_rejected(self) -> None:
        gui = IMPORT + "_APPROVED_SERVER_SOURCE_SHA256 = PUBLISHED_SERVER_SOURCE_SHA256\n" + PINS
        for downloader in (
            'PUBLISHED_SERVER_SOURCE_SHA256 = "a" * 64\n',
            f'PUBLISHED_SERVER_SOURCE_SHA256 = "{HASH}"\n'
            f'PUBLISHED_SERVER_SOURCE_SHA256 = "{OTHER}"\n',
            f'PUBLISHED_SERVER_SOURCE_SHA256 = "{HASH}"\n'
            f'if True:\n    PUBLISHED_SERVER_SOURCE_SHA256 = "{OTHER}"\n',
        ):
            with self.subTest(downloader=downloader):
                temporary, root = self.fixture(gui, downloader)
                with temporary, self.assertRaises(RuntimeError):
                    approved_release_pins(source_root=root)

    def test_literal_gui_pin_still_works_without_import(self) -> None:
        gui = f'_APPROVED_SERVER_SOURCE_SHA256 = "{HASH}"\n' + PINS
        temporary, root = self.fixture(gui, 'PUBLISHED_SERVER_SOURCE_SHA256 = untrusted_call()\n')
        with temporary:
            pins = approved_release_pins(source_root=root)
        self.assertEqual(pins["_APPROVED_SERVER_SOURCE_SHA256"], HASH)


if __name__ == "__main__":
    unittest.main()
