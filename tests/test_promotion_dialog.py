# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Actual Tk review flow, enabled in CI under Xvfb."""
from __future__ import annotations

import os
from pathlib import Path
import time
import unittest
from unittest.mock import patch

from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.installer import BundleSummary
from sovagrid_connect.promotion import PromotionPreview
from sovagrid_connect.promotion_protocol import PromotionState


GUI_TESTS = os.environ.get("SOVAGRID_GUI_TESTS") == "1"
if GUI_TESTS:
    import tkinter as tk
    from sovagrid_connect.promotion_dialog import PromotionDialog


class Theme:
    def style_window(self, _window):
        pass

    def style_text(self, _widget):
        pass


@unittest.skipUnless(GUI_TESTS, "actual Tk test; run under Xvfb with SOVAGRID_GUI_TESTS=1")
class PromotionDialogActualTk(unittest.TestCase):
    def test_review_shows_route_and_hash_without_mutation(self):
        root = tk.Tk()
        root.withdraw()
        self.addCleanup(root.destroy)
        errors, closed, ready = [], [], []
        root.report_callback_exception = lambda *args: errors.append(args)
        options = ConnectionOptions(host="target.example", user="exampleuser", port=2222,
                                    jump_host="relay.example", jump_user="root", jump_port=22)
        sha, manifest = "a" * 64, "b" * 64
        state = PromotionState("prepared", True, "c" * 64, manifest, None, None, None)
        preview = PromotionPreview(options.validated(), BundleSummary(Path("/tmp/bundle.tar.gz"),
                                   1200, 260, {"sovagrid-blueprint": "d" * 40}), sha, manifest, state)

        class Controller:
            apply_calls = 0
            def __init__(self, selected, *, approved_archive_sha256, progress):
                self.selected = selected
                self.progress = progress
                self.approved = approved_archive_sha256

            def preview(self, selected):
                assert str(selected) == "/tmp/chosen.tar.gz"
                assert self.approved == sha
                return preview

            def apply(self, *_args):
                Controller.apply_calls += 1
                raise AssertionError("preview must not install")

        with patch("sovagrid_connect.promotion_dialog.nearby_server_bundle",
                   return_value=(Path("/tmp/bundle.tar.gz"), sha)), patch(
                   "sovagrid_connect.promotion_dialog.PromotionController", Controller), patch(
                   "sovagrid_connect.promotion_dialog.filedialog.askopenfilename",
                   return_value="/tmp/chosen.tar.gz"):
            dialog = PromotionDialog(root, Theme(), options.validated(),
                                     lambda: closed.append(True), lambda *args: ready.append(args),
                                     approved_sha256=sha)
            root.update()
            self.assertIn("Выберите пакет", dialog.status.get())
            self.assertIn("exampleuser@target.example:2222 через root@relay.example:22",
                          str(dialog.route_label.cget("text")))
            self.assertEqual(str(dialog.apply_button.cget("state")), "disabled")
            dialog._choose()
            self.assertEqual(dialog.source.get(), "/tmp/chosen.tar.gz")
            dialog.check_button.invoke()
            deadline = time.monotonic() + 4
            while dialog.preview_result is None and time.monotonic() < deadline:
                root.update()
                time.sleep(.01)
            root.update()
            self.assertIsNotNone(dialog.preview_result, dialog.status.get())
            shown = dialog.details.get("1.0", "end")
            self.assertIn("exampleuser@target.example:2222", shown)
            self.assertIn(sha, shown)
            self.assertEqual(str(dialog.apply_button.cget("state")), "normal")
            self.assertEqual(Controller.apply_calls, 0)
            dialog.close()
        self.assertEqual(closed, [True])
        self.assertEqual(ready, [])
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
