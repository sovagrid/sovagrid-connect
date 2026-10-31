# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The portable backup form requires review and keeps paired export explicit."""

from pathlib import Path
import queue
import sys
import threading
import types
import unittest
from unittest import mock

from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.host_backup import (HostArchive, HostBackupOperation,
                                          HostBackupPlan, HostBackupState,
                                          HostPortableOperation, HostPortablePair)

try:
    import tkinter
except ImportError:
    toolkit = types.ModuleType("tkinter")
    toolkit.filedialog, toolkit.messagebox, toolkit.ttk = (
        types.ModuleType(name) for name in ("filedialog", "messagebox", "ttk"))
    with mock.patch.dict(sys.modules, {"tkinter": toolkit}):
        from sovagrid_connect import host_backup_dialog as dialog_module
else:
    from sovagrid_connect import host_backup_dialog as dialog_module


REQUEST = "a" * 32
ARCHIVE = "b" * 32
MANIFEST = "c" * 64


class Variable:
    def __init__(self):
        self.value = ""

    def set(self, value):
        assert threading.current_thread() is threading.main_thread()
        self.value = value


class Control:
    def __init__(self):
        self.state = None
        self.after_calls = []

    def configure(self, *, state):
        self.state = state

    def after(self, duration, callback):
        self.after_calls.append((duration, callback))
        return "next-pump"


class Selection:
    def selection(self):
        return ()


class Controller:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def start_portable(self, state, request):
        self.calls.append(("start", state, request))
        return self.result

    def verify_portable(self, request):
        self.calls.append(("verify", request))
        return self.result

    def export_portable(self, request, destination):
        self.calls.append(("export", request, destination))
        return destination / ("sovagrid-backup-" + ARCHIVE)

    def saved_request(self):
        return None

    def inspect(self):
        self.calls.append(("inspect",))
        return self.result

    def portable_available(self):
        self.calls.append(("portable_available",))
        return False


def fixture():
    dialog = dialog_module.HostBackupDialog.__new__(dialog_module.HostBackupDialog)
    dialog.options = ConnectionOptions("hub.example.invalid", "root")
    dialog.approved_manifest_sha256 = MANIFEST
    dialog.state = HostBackupState(dialog.options, MANIFEST, (),
                                   HostBackupPlan("full", (), (), True))
    dialog.request_id = None
    dialog.operation = None
    dialog.portable_mode = False
    dialog.portable_available = True
    dialog.portable_pair = None
    dialog.exported_path = None
    dialog.verified = None
    dialog.busy = dialog.closed = False
    dialog.status = Variable()
    dialog.window = Control()
    dialog.list = Selection()
    dialog.events = queue.SimpleQueue()
    dialog._next_poll = float("inf")
    dialog._show = mock.Mock()
    for name in ("refresh_button", "verify_button", "create_button", "close_button",
                 "status_button", "recover_button", "history_button", "portable_button",
                 "portable_verify_button", "portable_export_button"):
        setattr(dialog, name, Control())
    calls = []
    dialog._run = lambda kind, operation: calls.append((kind, operation))
    return dialog, calls


def completed_pair():
    archive = HostArchive(ARCHIVE, "2026-10-31T10:00:00+00:00", "full", 1024, 7, True)
    operation = HostBackupOperation(REQUEST, "complete", archive, None,
                                    "2026-10-31T10:00:00+00:00")
    return HostPortablePair(operation, archive,
                            {"images": {"hub": "sha256:" + "d" * 64,
                                        "web": "sha256:" + "e" * 64}},
                            2, 2048, {"hub": {"os": "linux", "architecture": "amd64"},
                                      "web": {"os": "linux", "architecture": "amd64"}})


class HostBackupDialogTest(unittest.TestCase):
    def test_refresh_disables_portable_on_older_verified_server(self):
        dialog, tasks = fixture()
        controller = Controller(dialog.state)
        dialog._controller = lambda: controller
        dialog.refresh()
        self.assertEqual(tasks[0][0], "refreshed")
        state, available = tasks[0][1]()
        self.assertIs(state, controller.result)
        self.assertFalse(available)
        self.assertEqual(controller.calls, [("inspect",), ("portable_available",)])
        dialog.portable_available = False
        with mock.patch.object(dialog_module.messagebox, "askyesno", return_value=True,
                               create=True):
            dialog.create_portable()
        self.assertEqual(len(tasks), 1)
        dialog.state = state
        dialog._controls()
        self.assertEqual(dialog.portable_button.state, "disabled")
        self.assertEqual(dialog.create_button.state, "normal")

    def test_portable_create_requires_review_confirmation(self):
        dialog, tasks = fixture()
        controller = Controller(None)
        dialog._controller = lambda: controller
        with mock.patch.object(dialog_module.messagebox, "askyesno", return_value=False,
                               create=True):
            dialog.create_portable()
        self.assertEqual(tasks, [])
        self.assertIsNone(dialog.request_id)
        with mock.patch.object(dialog_module.messagebox, "askyesno", return_value=True,
                               create=True):
            dialog.create_portable()
        self.assertTrue(dialog.portable_mode)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0][0], "portable_started")
        tasks[0][1]()
        self.assertEqual(controller.calls, [("start", dialog.state, dialog.request_id)])

    def test_export_requires_verified_pair_and_destination_confirmation(self):
        dialog, tasks = fixture()
        pair = completed_pair()
        controller = Controller(pair)
        dialog._controller = lambda: controller
        dialog.request_id, dialog.operation, dialog.portable_mode = REQUEST, pair.operation, True
        dialog.export_portable()
        self.assertEqual(tasks, [])
        dialog.portable_pair = pair
        with mock.patch.object(dialog_module.filedialog, "askdirectory", return_value="",
                               create=True):
            dialog.export_portable()
        self.assertEqual(tasks, [])
        with (mock.patch.object(dialog_module.filedialog, "askdirectory", return_value="/tmp/export", create=True),
              mock.patch.object(dialog_module.messagebox, "askyesno", return_value=False, create=True)):
            dialog.export_portable()
        self.assertEqual(tasks, [])
        with (mock.patch.object(dialog_module.filedialog, "askdirectory", return_value="/tmp/export", create=True),
              mock.patch.object(dialog_module.messagebox, "askyesno", return_value=True, create=True)):
            dialog.export_portable()
        self.assertEqual(tasks[0][0], "portable_exported")
        self.assertEqual(tasks[0][1](), Path("/tmp/export") / ("sovagrid-backup-" + ARCHIVE))
        self.assertEqual(controller.calls, [("export", REQUEST, Path("/tmp/export"))])

    def test_portable_controls_and_completion(self):
        dialog, tasks = fixture()
        pair = completed_pair()
        controller = Controller(pair)
        dialog._controller = lambda: controller
        dialog.request_id = REQUEST
        dialog.portable_mode = True
        dialog.operation = pair.operation
        dialog.portable_available = False
        dialog.events.put(("operation", pair.operation))
        dialog._pump()
        self.assertTrue(dialog.portable_available)
        dialog._controls()
        self.assertEqual(dialog.portable_verify_button.state, "normal")
        self.assertEqual(dialog.portable_export_button.state, "disabled")
        dialog.portable_pair = pair
        dialog._controls()
        self.assertEqual(dialog.portable_export_button.state, "normal")
        dialog._render_operation(pair.operation)
        self.assertIs(dialog.portable_pair, pair)
        self.assertIn("Архив и образы проверены", dialog.status.value)
        dialog.events.put(("portable_verified", pair))
        dialog._pump()
        self.assertIn("Архив, образы и квитанция проверены", dialog.status.value)
        exported = Path("/tmp/export") / ("sovagrid-backup-" + ARCHIVE)
        dialog.events.put(("portable_exported", exported))
        dialog._pump()
        self.assertEqual(dialog.exported_path, exported)
        self.assertIn(str(exported), dialog.status.value)
        dialog._render_operation(pair.operation)
        self.assertIn(str(exported), dialog.status.value)
        dialog.verify_portable()
        self.assertIsNone(dialog.portable_pair)
        self.assertIsNone(dialog.exported_path)
        self.assertEqual(tasks[-1][0], "portable_verified")
        self.assertIs(tasks[-1][1](), pair)


if __name__ == "__main__":
    unittest.main()
