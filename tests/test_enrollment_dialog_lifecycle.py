# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Exercise real dialog lifecycle methods without constructing a Tk root."""

import copy
import queue
import sys
import threading
import time
import types
import unittest
from unittest import mock

try:
    import tkinter
except ImportError:
    toolkit = types.ModuleType("tkinter")
    toolkit.filedialog, toolkit.messagebox, toolkit.ttk = (
        types.ModuleType(name) for name in ("filedialog", "messagebox", "ttk"))
    toolkit.messagebox.askyesno = lambda *_args, **_kwargs: False
    with mock.patch.dict(sys.modules, {"tkinter": toolkit}):
        from sovagrid_connect import enrollment_dialog as dialog_module
else:
    from sovagrid_connect import enrollment_dialog as dialog_module

EnrollmentDialog = dialog_module.EnrollmentDialog


class Variable:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        assert threading.current_thread() is threading.main_thread()
        return self.value

    def set(self, value):
        assert threading.current_thread() is threading.main_thread()
        self.value = value


class Control:
    def __init__(self):
        self.options = {}
        self.text = ""
        self.destroyed = False

    def configure(self, **options):
        assert threading.current_thread() is threading.main_thread()
        self.options.update(options)

    def after(self, *_args):
        assert threading.current_thread() is threading.main_thread()

    def yview_moveto(self, *_args):
        assert threading.current_thread() is threading.main_thread()

    def delete(self, *_args):
        self.text = ""

    def insert(self, _index, text):
        self.text = text

    def grab_release(self):
        pass

    def destroy(self):
        self.destroyed = True


class Fixture:
    def __init__(self):
        self.records = {}
        self.controllers = []
        self.instance = EnrollmentDialog.__new__(EnrollmentDialog)
        d = self.instance
        d.busy = d.closed = d.close_requested = d.cleanup_requested = d.reviewed = False
        d.controller = d.progress_binding = None
        d.generation = 0
        d.events = queue.SimpleQueue()
        d.records = {}
        d.selection = Variable("Новая установка")
        d.status = Variable()
        d.fields = {key: Variable(value) for key, value in {
            "name": "Fixture", "host": "target.example", "user": "root", "port": "22",
            "identity": "", "jump_host": "", "jump_user": "", "jump_port": "22",
            "jump_identity": "", "host_key_alias": "", "jump_host_key_alias": "",
            "hub_host": "192.0.2.1", "hub_port": "22", "agent_port": "18767",
            "bundle": "/fixture/source.tar.gz", "username": "owner", "password": "fixture-only",
        }.items()}
        d.entries = {key: Control() for key in d.fields}
        d.input_controls = list(d.entries.values())
        d.window, d.canvas, d.preview = Control(), Control(), Control()
        for name in ("record_choice", "profile_choice", "profile_file_button", "check_button",
                     "apply_button", "cleanup_button", "close_button"):
            setattr(d, name, Control())
        d.on_closed = mock.Mock()
        d.tunnel = object()
        d.journal = types.SimpleNamespace(list=lambda: copy.deepcopy(list(self.records.values())))
        d.controller_factory = self.controller_factory

    def controller_factory(self, _tunnel, *, journal, progress):
        owner = self

        class Controller:
            def __init__(self):
                self.record = None
                self.progress = progress
                self.apply_entered, self.release_apply = threading.Event(), threading.Event()
                self.cancel = mock.Mock()
                self.cleanup = mock.Mock()
                self.close = mock.Mock()

            def prepare(self, *, target_options, name, bundle, hub_host, hub_port, local_port, credentials):
                identifier = "fixture-request-" + str(len(owner.controllers))
                self.record = {
                    "request_id": identifier, "name": name, "phase": "prepared", "cleanup_required": False,
                    "target_connection": {"host": target_options.host, "user": target_options.user,
                                          "port": target_options.port},
                    "hub_endpoint": {"host": hub_host, "port": hub_port, "local_port": local_port},
                    "bundle": {"path": bundle, "sha256": "a" * 64},
                }
                owner.records[identifier] = self.record
                self.progress("Проверяем серверы")
                return {"record": copy.deepcopy(self.record), "platform": {
                    "ubuntu_version": "24.04", "python_version": "3.12"}, "hub_fingerprint": "SHA256:fixture"}

            def apply(self):
                self.progress("Ожидаем первое измерение: " + self.record["request_id"])
                self.apply_entered.set()
                if not self.release_apply.wait(3):
                    raise RuntimeError("Test worker was not released")
                self.record["phase"] = "active"
                return copy.deepcopy(self.record)

        controller = Controller()
        self.controllers.append(controller)
        return controller

    def until(self, predicate):
        deadline = time.monotonic() + 3
        while not predicate() and time.monotonic() < deadline:
            self.instance.pump()
            time.sleep(.005)
        self.instance.pump()
        if not predicate():
            raise AssertionError("Dialog worker did not finish: " + self.instance.status.get())

    def check(self):
        self.instance.check()
        self.until(lambda: not self.instance.busy)
        if not self.instance.reviewed:
            raise AssertionError(self.instance.status.get())


class EnrollmentDialogLifecycleTests(unittest.TestCase):
    def test_apply_shows_live_progress_and_replaced_controller_cannot_overwrite_it(self):
        fixture = Fixture()
        d = fixture.instance
        fixture.check()
        first = d.controller
        self.addCleanup(first.release_apply.set)
        d.apply()
        self.assertTrue(first.apply_entered.wait(1))
        d.pump()
        self.assertTrue(d.busy)
        self.assertEqual(d.status.get(), "Ожидаем первое измерение: " + first.record["request_id"])
        first.release_apply.set()
        fixture.until(lambda: not d.busy)

        d.selection.set("Новая установка")
        d._select_record()
        fixture.check()
        second = d.controller
        self.addCleanup(second.release_apply.set)
        self.assertIsNot(first, second)
        d.apply()
        self.assertTrue(second.apply_entered.wait(1))
        first.progress("Late progress from previous server")
        d.pump()
        self.assertTrue(d.busy)
        self.assertEqual(d.status.get(), "Ожидаем первое измерение: " + second.record["request_id"])
        second.release_apply.set()
        fixture.until(lambda: not d.busy)
        d.close()
        fixture.until(lambda: d.closed)

    def test_cleanup_revalidates_context_after_modal_confirmation(self):
        for mutation in ("close", "selection"):
            with self.subTest(mutation=mutation):
                fixture = Fixture()
                d = fixture.instance
                fixture.check()
                original = d.controller

                def confirm(*_args, **_kwargs):
                    if mutation == "close":
                        d.close()
                    else:
                        d.selection.set("Новая установка")
                        d._select_record()
                    return True

                with mock.patch.object(dialog_module.messagebox, "askyesno", side_effect=confirm, create=True):
                    d.request_cleanup()
                original.cancel.assert_not_called()
                original.cleanup.assert_not_called()
                self.assertFalse(d.cleanup_requested)
                if mutation != "close":
                    d.close()
                fixture.until(lambda: d.closed)
                d.on_closed.assert_called_once()


if __name__ == "__main__":
    unittest.main()
