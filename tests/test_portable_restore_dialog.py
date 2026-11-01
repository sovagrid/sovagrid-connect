# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Confirmation binds the visible plan; lost acknowledgments retain recovery."""
from copy import deepcopy
from pathlib import Path
import queue
import sys
import types
import unittest
from unittest.mock import patch

from sovagrid_connect.core import ConnectionOptions

try:
    import tkinter
except ImportError:
    toolkit = types.ModuleType("tkinter")
    toolkit.filedialog, toolkit.messagebox, toolkit.ttk = (
        types.ModuleType(name) for name in ("filedialog", "messagebox", "ttk"))
    with patch.dict(sys.modules, {"tkinter": toolkit}):
        from sovagrid_connect import portable_restore_dialog as module
else:
    from sovagrid_connect import portable_restore_dialog as module


class Variable:
    def __init__(self, value=""):
        self.value = value

    def set(self, value):
        self.value = value

    def get(self):
        return self.value


class RestoreConfirmationTests(unittest.TestCase):
    def setUp(self):
        view = module.PortableRestoreDialog.__new__(module.PortableRestoreDialog)
        view.window = object()
        view.options = ConnectionOptions("server.example.org", user="ubuntu").validated()
        view.record = {"operation_id": "a" * 32, "request": {"archive_id": "b" * 32}}
        view.reply = {"phase": "review", "apply_available": True, "apply_review_sha256": "c" * 64,
                      "blockers": [], "registered": True}
        view.status, view.folder = Variable(), Variable(str(Path.cwd() / "copy"))
        view.busy = view.closed = False
        view.controls = lambda: None
        self.calls = []
        controller = types.SimpleNamespace(action=lambda *args, **kwargs: self.calls.append((args, kwargs)))
        view.run = lambda task: task(controller)
        self.view = view

    def test_declining_confirmation_never_sends_start(self):
        with patch.object(module.messagebox, "askyesno", return_value=False, create=True):
            self.view.apply()
        self.assertEqual(self.calls, [])

    def test_start_uses_exact_review_and_operation_presented_to_user(self):
        saved = deepcopy(self.view.record)
        with patch.object(module.messagebox, "askyesno", return_value=True, create=True) as question:
            self.view.apply()
        self.assertIn("ubuntu@server.example.org", question.call_args.args[1])
        self.assertIn(saved["request"]["archive_id"], question.call_args.args[1])
        self.assertEqual(self.calls, [((saved, "start"), {"apply_review_sha256": "c" * 64})])

    def test_changed_review_during_modal_loop_does_not_apply_the_replacement(self):
        def confirm(*_args, **_kwargs):
            self.view.reply["apply_review_sha256"] = "d" * 64
            return True

        with patch.object(module.messagebox, "askyesno", side_effect=confirm, create=True):
            self.view.apply()
        self.assertEqual(self.calls, [])
        self.assertIsNone(self.view.reply)
        self.assertIn("изменился", self.view.status.value)

    def test_backend_disabled_never_opens_apply_confirmation(self):
        self.view.reply["apply_available"] = False
        with patch.object(module.messagebox, "askyesno", create=True) as confirm:
            self.view.apply()
            confirm.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_registered_copy_can_get_new_plan_without_local_files_or_dependency_prompt(self):
        self.view.reply["phase"] = "ready"
        self.view.reply["apply_available"] = False
        with patch.object(module.messagebox, "askyesno", create=True) as confirm:
            self.view.prepare()
            confirm.assert_not_called()
        self.assertEqual(self.calls, [((self.view.record, "preview"), {})])

    def test_changed_retry_terminal_is_not_confirmed_by_old_dialog(self):
        self.view.reply.update(retry_available=True, terminal_sha256="e" * 64)

        def confirm(*_args, **_kwargs):
            self.view.reply["terminal_sha256"] = "f" * 64
            return True

        with patch.object(module.messagebox, "askyesno", side_effect=confirm, create=True):
            self.view.retry()
        self.assertEqual(self.calls, [])
        self.assertIsNone(self.view.reply)

    def test_lost_prepare_ack_keeps_saved_operation_and_clears_stale_plan(self):
        view = self.view
        saved = deepcopy(view.record)
        view.record = None
        view.events = queue.SimpleQueue()
        view.events.put(("error", ("SSH прерван.", saved)))
        view.progress = types.SimpleNamespace(stop=lambda: None)
        view.reload_history = lambda: None
        view.show = lambda text: setattr(view, "shown", text)
        view.window = types.SimpleNamespace(after=lambda *args: "next")
        view.next_poll = 0
        view.pump()
        self.assertEqual(view.record, saved)
        self.assertIsNone(view.reply)
        self.assertIn(saved["operation_id"], view.shown)
        self.assertIn("Проверьте состояние", view.status.value)


if __name__ == "__main__":
    unittest.main()
