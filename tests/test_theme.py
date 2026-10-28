# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from sovagrid_connect.theme import CHOICES, LABELS, load_preference, save_preference


class ThemePreferenceTests(unittest.TestCase):
    def test_three_choices_round_trip_without_credentials(self) -> None:
        self.assertEqual(set(LABELS), {"system", "light", "dark"})
        self.assertEqual(set(CHOICES.values()), set(LABELS))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "preferences.json"
            self.assertEqual(load_preference(path), "system")
            for name in LABELS:
                with self.subTest(name=name):
                    self.assertTrue(save_preference(name, path))
                    self.assertEqual(load_preference(path), name)
                    self.assertEqual(json.loads(path.read_text()), {"theme": name})
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_invalid_or_symlinked_preferences_fall_back_to_system(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "preferences.json"
            for data in ('not json', '{"theme":"unknown"}', 'x' * 4097):
                path.write_text(data)
                self.assertEqual(load_preference(path), "system")
            target = Path(directory) / "target.json"
            target.write_text('{"theme":"dark"}')
            path.unlink()
            try:
                path.symlink_to(target)
            except OSError:
                pass
            else:
                self.assertEqual(load_preference(path), "system")
            self.assertFalse(save_preference("invalid", path))


if __name__ == "__main__":
    unittest.main()
