# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Real Tk review and stale-state gates for local command permission."""

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
class LocalCommandsDialogTests(unittest.TestCase):
    def test_review_cas_refusal_requires_new_preview_before_explicit_enable(self):
        from sovagrid_connect.core import ConnectionOptions
        from sovagrid_connect.installer import InstallError
        from sovagrid_connect.local_commands import LocalCommandsState
        from sovagrid_connect import local_commands_dialog as module

        root = tk.Tk()
        self.addCleanup(root.destroy)
        root.geometry("550x430")
        root.update()
        options = ConnectionOptions(host="target.example.org", user="exampleuser",
                                    jump_host="relay.example.org", jump_user="relay").validated()
        common = (options, "3" * 64, "c432d4dc-3cf2-4929-947c-8869fb85bff9")
        disabled = LocalCommandsState(*common, False, True, "a" * 64)
        enabled = LocalCommandsState(*common, True, True, "b" * 64)
        controller = Mock()
        controller.preview.return_value = disabled
        controller.enable.side_effect = InstallError("Состояние локального Agent изменилось; повторите проверку")
        theme = types.SimpleNamespace(style_window=lambda _window: None,
                                      style_text=lambda _text: None)
        errors, confirmations = [], []

        def confirm(_title, message, **_kwargs):
            confirmations.append(message)
            return True

        with patch.object(module, "LocalCommandsController", return_value=controller), \
             patch.object(module.messagebox, "askyesno", side_effect=confirm), \
             patch.object(module.messagebox, "showerror",
                          side_effect=lambda *args, **_kwargs: errors.append(args)):
            dialog = module.LocalCommandsDialog(root, theme, options, lambda: None,
                                                approved_manifest_sha256="3" * 64)
            dialog.window.geometry("760x440")
            root.update()
            self.assertIn("relay.example.org", str(dialog.route_label.cget("text")))
            self.assertEqual(str(dialog.enable_button.cget("state")), "disabled")

            def until_state(expected):
                deadline = time.monotonic() + 5
                while dialog.state is not expected and time.monotonic() < deadline:
                    root.update()
                    time.sleep(.01)
                self.assertIs(dialog.state, expected, str(errors))

            dialog.check_button.invoke()
            until_state(disabled)
            self.assertEqual(str(dialog.enable_button.cget("state")), "normal")
            self.assertIn("3" * 64, dialog.details.get("1.0", "end"))
            dialog.enable_button.invoke()
            deadline = time.monotonic() + 5
            while dialog.busy and time.monotonic() < deadline:
                root.update()
                time.sleep(.01)
            self.assertFalse(dialog.busy)
            self.assertIsNone(dialog.state)
            self.assertEqual(str(dialog.enable_button.cget("state")), "disabled")
            self.assertEqual(str(dialog.check_button.cget("state")), "normal")
            self.assertEqual(len(errors), 1)
            self.assertIn("Ревизия:", confirmations[0])
            self.assertIn("Локальный Agent:", confirmations[0])

            controller.enable.side_effect = None
            controller.enable.return_value = enabled
            dialog.check_button.invoke()
            until_state(disabled)
            dialog.enable_button.invoke()
            until_state(enabled)
            self.assertEqual(str(dialog.enable_button.cget("state")), "disabled")
            self.assertIn("разрешены", dialog.details.get("1.0", "end"))
            self.assertEqual(controller.enable.call_count, 2)
            dialog.close()

    def test_unapproved_release_disables_check_without_remote_access(self):
        from sovagrid_connect.core import ConnectionOptions
        from sovagrid_connect import local_commands_dialog as module

        root = tk.Tk()
        self.addCleanup(root.destroy)
        root.update()
        options = ConnectionOptions(host="target.example.org", user="root").validated()
        theme = types.SimpleNamespace(style_window=lambda _window: None,
                                      style_text=lambda _text: None)
        with patch.object(module, "LocalCommandsController") as controller:
            dialog = module.LocalCommandsDialog(root, theme, options, lambda: None,
                                                approved_manifest_sha256=None)
            root.update()
            self.assertEqual(str(dialog.check_button.cget("state")), "disabled")
            self.assertEqual(str(dialog.enable_button.cget("state")), "disabled")
            controller.assert_not_called()
            dialog.close()


if __name__ == "__main__":
    unittest.main()
