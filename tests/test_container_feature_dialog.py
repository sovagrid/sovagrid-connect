# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The managed Hub container choice is explicit and usable in a short Tk window."""
import os
import time
import unittest
from unittest.mock import Mock, patch

try:
    import tkinter as tk
except ImportError:
    tk = None


@unittest.skipUnless(tk is not None and os.environ.get("SOVAGRID_GUI_TESTS") == "1",
                     "actual Tk test; run under Xvfb with SOVAGRID_GUI_TESTS=1")
class ContainerFeatureDialogTests(unittest.TestCase):
    def test_opt_in_review_shows_root_socket_warning_and_passes_checked_state(self):
        from sovagrid_connect.core import ConnectionOptions
        from sovagrid_connect.gui import Launcher
        from sovagrid_connect.installer import FeatureState

        root = tk.Tk()
        self.addCleanup(root.destroy)
        root.geometry("650x480")
        root.update()
        with patch("sovagrid_connect.theme.load_preference", return_value="system"):
            launcher = Launcher(root)
        options = ConnectionOptions(host="fixture.example.org", user="root")
        with patch.object(launcher, "_options", return_value=options):
            launcher.open_features()
        window = launcher.feature_window
        self.assertIsNotNone(window)
        window.geometry("560x430")
        root.update()
        self.assertEqual(len(launcher.feature_checks), 7)
        self.assertIn("контейнеров", str(launcher.feature_checks[5].cget("text")))
        self.assertTrue(launcher.feature_start_button.winfo_ismapped())
        self.assertLessEqual(launcher.feature_start_button.winfo_rooty() +
                             launcher.feature_start_button.winfo_height(),
                             window.winfo_rooty() + window.winfo_height())
        launcher.feature_checks[5].invoke()
        checked = FeatureState(False, False, False, containers_supported=True, cas_sha256="a" * 64)
        fake = Mock()
        fake.preflight_features.return_value = checked
        review = []

        def confirm(_title, detail, **_kwargs):
            review.append(detail)
            return True

        with patch("sovagrid_connect.gui.ServerInstaller", return_value=fake), \
             patch("sovagrid_connect.gui.messagebox.askyesno", side_effect=confirm), \
             patch("sovagrid_connect.gui.messagebox.showinfo"):
            launcher.feature_start_button.invoke()
            deadline = time.monotonic() + 5
            while not fake.enable_features.called and time.monotonic() < deadline:
                root.update()
                launcher.pump()
                time.sleep(.01)
            self.assertTrue(fake.enable_features.called)
            self.assertEqual(fake.enable_features.call_args.kwargs["expected_state"], checked)
            self.assertTrue(fake.enable_features.call_args.args[0].containers)
            while launcher.installing and time.monotonic() < deadline:
                root.update()
                launcher.pump()
                time.sleep(.01)
            self.assertFalse(launcher.installing)
            launcher.close_features()
        self.assertTrue(review)
        self.assertIn("root-сборщик", review[0])
        self.assertIn("Engine socket", review[0])


if __name__ == "__main__":
    unittest.main()
