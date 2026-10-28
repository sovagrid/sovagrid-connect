# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
import contextlib
import io
import re
from pathlib import Path
import unittest

from sovagrid_connect.__main__ import main
from sovagrid_connect import __version__
from sovagrid_connect.legal import document, third_party_document, third_party_documents


class LegalDistributionTests(unittest.TestCase):
    def test_visible_version_matches_distribution_metadata(self):
        project = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
        self.assertEqual(__version__, re.search(r'^version = "([^"]+)"', project, re.MULTILINE).group(1))
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as exit_status:
            main(["--version"])
        self.assertEqual(exit_status.exception.code, 0)
        self.assertIn(f"SovaGrid Connect {__version__}", output.getvalue())

    def test_bundled_notices_match_repository_license(self):
        root = Path(__file__).resolve().parents[1]
        for name in ("LICENSE", "ATTRIBUTION.md", "NOTICE"):
            self.assertEqual(document(name), (root / name).read_text(encoding="utf-8"))
        with self.assertRaises(ValueError):
            document("../README.md")

    def test_cli_can_display_license_and_attribution_offline(self):
        for arguments, expected in ((["license"], "GNU AFFERO GENERAL PUBLIC LICENSE"),
                                    (["license", "--attribution"], "Jigokuraku01")):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(arguments), 0)
            self.assertIn(expected, output.getvalue())

    def test_third_party_texts_are_bundled_and_path_is_constrained(self):
        names = third_party_documents()
        self.assertIn("INDEX.md", names)
        self.assertIn("CPython-3.13.16-LICENSE", names)
        self.assertIn("tk-8.6.18-license.terms", names)
        self.assertIn("PyInstaller-6.22.3-COPYING.txt", names)
        self.assertIn("Python Software Foundation", third_party_document("CPython-3.13.16-LICENSE"))
        with self.assertRaises(ValueError):
            third_party_document("../LICENSE")

    def test_cli_can_read_third_party_notices_offline(self):
        for arguments, expected in ((["third-party-licenses"], "CPython 3.13.16"),
                                    (["third-party-licenses", "--list"], "tk-8.6.18-license.terms"),
                                    (["third-party-licenses", "zlib-1.3.1-LICENSE"], "Jean-loup Gailly")):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(arguments), 0)
            self.assertIn(expected, output.getvalue())
