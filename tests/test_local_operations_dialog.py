# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Real Tk review gates for the local Agent's PTY/files switches."""

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
class LocalOperationsDialogTests(unittest.TestCase):
    def test_check_then_single_feature_review_and_explicit_recovery(self):
        from sovagrid_connect.core import ConnectionOptions
        from sovagrid_connect.installer import InstallError
        from sovagrid_connect.local_operations import LocalOperationsState
        from sovagrid_connect import local_operations_dialog as module

        root = tk.Tk()
        self.addCleanup(root.destroy)
        root.geometry("550x430")
        root.update()
        options = ConnectionOptions(host="target.example.org", user="exampleuser",
                                    jump_host="relay.example.org", jump_user="relay").validated()
        common = (options, "a" * 64, "c432d4dc-3cf2-4929-947c-8869fb85bff9")
        ready = LocalOperationsState(*common, "ready", False, False, None, None, True, "a" * 64)
        enabled = LocalOperationsState(*common, "ready", True, False, None, None, True, "b" * 64)
        pending = LocalOperationsState(*common, "recovery_required", False, False, True, False, None, None)
        controller = Mock()
        controller.preview.return_value = ready
        controller.change.return_value = enabled
        controller.recover.return_value = ready
        theme = types.SimpleNamespace(style_window=lambda _window: None,
                                      style_text=lambda _text: None)
        errors = []
        confirmations = []

        def confirm(_title, message, **_kwargs):
            confirmations.append(message)
            return True

        with patch.object(module, "LocalOperationsController", return_value=controller), \
             patch.object(module.messagebox, "askyesno", side_effect=confirm), \
             patch.object(module.messagebox, "showerror",
                          side_effect=lambda *args, **_kwargs: errors.append(args)):
            dialog = module.LocalOperationsDialog(root, theme, options, lambda: None,
                                                  approved_manifest_sha256="a" * 64)
            dialog.window.geometry("760x510")
            root.update()
            self.assertIn("relay.example.org", str(dialog.route_label.cget("text")))
            self.assertEqual(str(dialog.terminal_button.cget("state")), "disabled")
            self.assertEqual(str(dialog.files_button.cget("state")), "disabled")
            self.assertEqual(str(dialog.recover_button.cget("state")), "disabled")

            def until(expected):
                deadline = time.monotonic() + 5
                while dialog.state is not expected and time.monotonic() < deadline:
                    root.update()
                    time.sleep(.01)
                self.assertIs(dialog.state, expected, str(errors))

            dialog.check_button.invoke()
            until(ready)
            self.assertIn("a" * 64, dialog.details.get("1.0", "end"))
            self.assertEqual(str(dialog.terminal_button.cget("state")), "normal")
            dialog.terminal_button.invoke()
            until(enabled)
            controller.change.assert_called_once_with("terminal", True, ready)
            self.assertIn("Манифест:", confirmations[0])
            self.assertIn("Локальный Agent:", confirmations[0])
            self.assertIn("Ревизия настроек:", confirmations[0])
            self.assertIn("Выключить терминал", str(dialog.terminal_button.cget("text")))

            controller.preview.return_value = pending
            dialog.check_button.invoke()
            until(pending)
            self.assertEqual(str(dialog.terminal_button.cget("state")), "disabled")
            self.assertEqual(str(dialog.files_button.cget("state")), "disabled")
            self.assertEqual(str(dialog.recover_button.cget("state")), "normal")
            self.assertIn("Незавершённая операция", dialog.details.get("1.0", "end"))
            dialog.recover_button.invoke()
            until(ready)
            controller.recover.assert_called_once_with(pending)

            # A server side CAS refusal clears the reviewed revision. No
            # feature action is available until the user requests preview.
            controller.change.side_effect = InstallError(
                "Настройки локального Agent изменились; повторите проверку")
            dialog.files_button.invoke()
            deadline = time.monotonic() + 5
            while dialog.busy and time.monotonic() < deadline:
                root.update()
                time.sleep(.01)
            self.assertFalse(dialog.busy)
            self.assertIsNone(dialog.state)
            self.assertEqual(str(dialog.files_button.cget("state")), "disabled")
            self.assertEqual(str(dialog.terminal_button.cget("state")), "disabled")
            self.assertEqual(str(dialog.check_button.cget("state")), "normal")
            self.assertEqual(len(errors), 1)
            controller.preview.return_value = ready
            dialog.check_button.invoke()
            until(ready)
            self.assertEqual(str(dialog.files_button.cget("state")), "normal")
            dialog.close()


if __name__ == "__main__":
    unittest.main()
