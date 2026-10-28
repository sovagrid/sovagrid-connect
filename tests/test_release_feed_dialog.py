# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Real Tk view of the reviewed signed-feed controls."""

import os
import time
import types
import unittest
from unittest.mock import Mock, patch

try:
    import tkinter as tk
except ImportError:
    tk = None


@unittest.skipUnless(tk is not None and os.environ.get("SOVAGRID_GUI_TESTS") == "1",
                     "actual Tk test; run under Xvfb with SOVAGRID_GUI_TESTS=1")
class ReleaseFeedDialogTests(unittest.TestCase):
    def test_status_without_revision_shows_key_but_cannot_mutate(self):
        from sovagrid_connect.core import ConnectionOptions
        from sovagrid_connect.release_feed import ReleaseFeedState
        from sovagrid_connect import release_feed_dialog as module

        root = tk.Tk()
        self.addCleanup(root.destroy)
        root.update()
        options = ConnectionOptions(host="target.example.org", user="admin",
                                    jump_host="relay.example.org", jump_user="relay").validated()
        state = ReleaseFeedState(options, "3" * 64, True, False, None,
                                 (("test-anchor", "a" * 64),), False, True, 2,
                                 "0.5.2", 1800000300)
        controller = Mock()
        controller.preview.return_value = state
        theme = types.SimpleNamespace(style_window=lambda _window: None,
                                      style_text=lambda _text: None)
        with patch.object(module, "ReleaseFeedController", return_value=controller):
            dialog = module.ReleaseFeedDialog(root, theme, options, lambda: None,
                                              approved_manifest_sha256="3" * 64)
            root.update()
            self.assertIn("relay.example.org", str(dialog.route_label.cget("text")))
            self.assertEqual(str(dialog.enable_button.cget("state")), "disabled")
            dialog.check_button.invoke()
            deadline = time.monotonic() + 5
            while dialog.state is None and time.monotonic() < deadline:
                root.update()
                time.sleep(.01)
            self.assertIs(dialog.state, state)
            details = dialog.details.get("1.0", "end")
            self.assertIn("test-anchor", details)
            self.assertIn("a" * 64, details)
            self.assertIn("один архив", details)
            self.assertIn("UTC", details)
            self.assertEqual(str(dialog.enable_button.cget("state")), "disabled")
            self.assertEqual(str(dialog.disable_button.cget("state")), "disabled")
            controller.enable.assert_not_called()
            controller.disable.assert_not_called()
            dialog.close()

    def test_reviewed_key_requires_confirmation_and_rechecks_result(self):
        from sovagrid_connect.core import ConnectionOptions
        from sovagrid_connect.release_feed import ReleaseFeedState
        from sovagrid_connect import release_feed_dialog as module

        root = tk.Tk()
        self.addCleanup(root.destroy)
        root.update()
        options = ConnectionOptions(host="target.example.org", user="admin").validated()
        initial = ReleaseFeedState(options, "3" * 64, True, False, None,
                                   (("test-anchor", "a" * 64),), False, True, 2,
                                   "0.5.2", 1800000300, False, "b" * 64)
        enabled = ReleaseFeedState(options, "3" * 64, True, True, "test-anchor",
                                   (("test-anchor", "a" * 64),), True, True, 2,
                                   "0.5.2", 1800000300, True, "c" * 64)
        controller = Mock()
        controller.enable.return_value = enabled
        theme = types.SimpleNamespace(style_window=lambda _window: None,
                                      style_text=lambda _text: None)
        with patch.object(module, "ReleaseFeedController", return_value=controller):
            dialog = module.ReleaseFeedDialog(root, theme, options, lambda: None,
                                              approved_manifest_sha256="3" * 64)
            dialog._render(initial)
            self.assertEqual(str(dialog.enable_button.cget("state")), "normal")
            with patch.object(module.messagebox, "askyesno", return_value=False):
                dialog.enable_button.invoke()
            controller.enable.assert_not_called()
            with patch.object(module.messagebox, "askyesno", return_value=True):
                dialog.enable_button.invoke()
            deadline = time.monotonic() + 5
            while dialog.state is not enabled and time.monotonic() < deadline:
                root.update()
                time.sleep(.01)
            self.assertIs(dialog.state, enabled)
            controller.enable.assert_called_once_with(initial, "test-anchor")
            self.assertEqual(str(dialog.enable_button.cget("state")), "disabled")
            self.assertEqual(str(dialog.disable_button.cget("state")), "normal")
            dialog.close()

    def test_removed_key_is_marked_untrusted_but_disable_is_available(self):
        from sovagrid_connect.core import ConnectionOptions
        from sovagrid_connect.release_feed import ReleaseFeedState
        from sovagrid_connect import release_feed_dialog as module

        root = tk.Tk()
        self.addCleanup(root.destroy)
        root.update()
        options = ConnectionOptions(host="target.example.org", user="admin").validated()
        state = ReleaseFeedState(options, "3" * 64, True, True, "retired-anchor", (),
                                 False, False, 3, "0.6.0", 1800000300, False, "b" * 64)
        theme = types.SimpleNamespace(style_window=lambda _window: None,
                                      style_text=lambda _text: None)
        dialog = module.ReleaseFeedDialog(root, theme, options, lambda: None,
                                          approved_manifest_sha256="3" * 64)
        dialog._render(state)
        self.assertIn("retired-anchor", dialog.details.get("1.0", "end"))
        self.assertIn("больше не встроен", dialog.details.get("1.0", "end"))
        self.assertEqual(str(dialog.enable_button.cget("state")), "disabled")
        self.assertEqual(str(dialog.disable_button.cget("state")), "normal")
        dialog.close()

    def test_unapproved_server_keeps_read_only_probe_disabled(self):
        from sovagrid_connect.core import ConnectionOptions
        from sovagrid_connect import release_feed_dialog as module

        root = tk.Tk()
        self.addCleanup(root.destroy)
        root.update()
        options = ConnectionOptions(host="target.example.org", user="root").validated()
        theme = types.SimpleNamespace(style_window=lambda _window: None,
                                      style_text=lambda _text: None)
        with patch.object(module, "ReleaseFeedController") as controller:
            dialog = module.ReleaseFeedDialog(root, theme, options, lambda: None,
                                              approved_manifest_sha256=None)
            root.update()
            self.assertEqual(str(dialog.check_button.cget("state")), "disabled")
            self.assertEqual(str(dialog.enable_button.cget("state")), "disabled")
            controller.assert_not_called()
            dialog.close()


if __name__ == "__main__":
    unittest.main()
