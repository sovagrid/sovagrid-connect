# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Credential, review and close boundaries of the remote Agent feature form."""
import copy
import os
from pathlib import Path
import queue
import sys
import threading
import tempfile
import time
from types import SimpleNamespace
import types
import unittest
from unittest.mock import Mock, patch

from sovagrid_connect.core import ConnectionOptions

try:
    import tkinter as tk
except ImportError:
    tk = None
    toolkit = types.ModuleType("tkinter")
    toolkit.filedialog, toolkit.messagebox, toolkit.ttk = (
        types.ModuleType(name) for name in ("filedialog", "messagebox", "ttk"))
    toolkit.messagebox.askyesno = lambda *_args, **_kwargs: False
    with patch.dict(sys.modules, {"tkinter": toolkit}):
        from sovagrid_connect import remote_features_dialog as dialog_module
else:
    from sovagrid_connect import remote_features_dialog as dialog_module

RemoteFeaturesDialog = dialog_module.RemoteFeaturesDialog
SERVER = "00000000-0000-4000-8000-000000000001"
OTHER = "00000000-0000-4000-8000-000000000002"
FLAGS = {"commands": False, "terminal": False, "files": False}


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
        return "fixture-after"
    def after_cancel(self, *_args):
        pass
    def delete(self, *_args):
        assert threading.current_thread() is threading.main_thread()
        self.text = ""
    def insert(self, _index, text):
        assert threading.current_thread() is threading.main_thread()
        self.text = text
    def yview_moveto(self, *_args):
        assert threading.current_thread() is threading.main_thread()
    def grab_release(self):
        pass
    def destroy(self):
        self.destroyed = True


class World:
    def __init__(self):
        self.controllers, self.calls, self.credential_references = [], [], []
        self.prepare_gate = self.apply_gate = self.close_gate = None
        self.prepare_entered, self.apply_entered, self.close_entered = (threading.Event() for _ in range(3))
        self.prepare_error = None
        self.cleanup_required = False
        self.recovery_required = False

    def factory(self, _tunnel, *, progress):
        world = self
        class Controller:
            def __init__(self):
                self.progress = progress
                self.cancel = Mock()
                self.info = None
            def list_servers(self, *, credentials=None):
                world.calls.append(("list",))
                if credentials is not None:
                    world.credential_references.append(credentials)
                self.progress("Список серверов проверен")
                return [{"id": SERVER, "name": "Target"}, {"id": OTHER, "name": "Other"}]
            def prepare(self, **arguments):
                world.calls.append(("prepare", arguments))
                world.prepare_entered.set()
                if world.prepare_gate is not None:
                    world.prepare_gate.wait(3)
                if world.prepare_error is not None:
                    raise world.prepare_error
                self.info = {"server_id": arguments["server_id"], "name": "Target", "current": copy.deepcopy(FLAGS),
                    "desired": copy.deepcopy(FLAGS), "hub": {"enabled": False, "revision": 0},
                    "identity": {"server_id": arguments["server_id"]},
                    "bundle": {"path": arguments["bundle"], "sha256": "a" * 64},
                    "source_commits": {}, "platform": {}, "change_required": False,
                    "recovery_required": world.recovery_required}
                return copy.deepcopy(self.info)
            def preview(self, features):
                world.calls.append(("preview", copy.deepcopy(features)))
                self.info["desired"] = copy.deepcopy(features)
                self.info["change_required"] = features != self.info["current"]
                return copy.deepcopy(self.info)
            def apply(self):
                world.calls.append(("apply",))
                world.apply_entered.set()
                if world.apply_gate is not None:
                    world.apply_gate.wait(3)
                result = copy.deepcopy(self.info)
                result["current"] = result["desired"]
                result["cleanup_required"] = world.cleanup_required
                return result
            def close(self):
                world.calls.append(("close",))
                world.close_entered.set()
                if world.close_gate is not None:
                    world.close_gate.wait(3)
        controller = Controller()
        self.controllers.append(controller)
        return controller


def fixture(world):
    d = RemoteFeaturesDialog.__new__(RemoteFeaturesDialog)
    d.tunnel = SimpleNamespace(alive=True, options=ConnectionOptions("hub.invalid", user="root"))
    d.controller_factory = world.factory
    d.controller = d.progress_binding = None
    d.prepared = d.review = d.prepared_context = d.pending_context = None
    d.authenticated = d.busy = d.closed = d.close_requested = False
    d.generation = 0
    d.events = queue.SimpleQueue()
    d.servers, d.catalog = {}, None
    d._syncing = False
    defaults = {"username": "admin", "password": "fixture-ui-secret", "host": "home.invalid", "user": "root",
        "port": "22", "identity": "", "jump_host": "vps.invalid", "jump_user": "root", "jump_port": "22",
        "jump_identity": "", "host_key_alias": "", "jump_host_key_alias": "", "bundle": "/fixture/source.tar.gz"}
    d.fields = {key: Variable(value) for key, value in defaults.items()}
    d.entries = {key: Control() for key in defaults}
    d.selection, d.profile, d.status = Variable(), Variable(), Variable()
    d.feature_values = {key: Variable(value) for key, value in FLAGS.items()}
    d.feature_checks = {key: Control() for key in FLAGS}
    for name in ("window", "server_choice", "profile_choice", "load_button", "check_button", "preview_button",
                 "apply_button", "close_button", "details", "canvas"):
        setattr(d, name, Control())
    d.input_controls = [*d.entries.values(), d.server_choice, d.profile_choice, d.load_button]
    d.on_closed = Mock()
    d._pump_after = None
    return d


class RemoteFeatureDialogLifecycle(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.dialog = fixture(self.world)
    def until(self, predicate):
        deadline = time.monotonic() + 4
        while not predicate() and time.monotonic() < deadline:
            self.dialog.pump()
            time.sleep(.005)
        self.dialog.pump()
        self.assertTrue(predicate(), "dialog worker did not finish")
    def idle(self):
        self.until(lambda: not self.dialog.busy)
    def prepared(self):
        self.dialog.load_servers()
        self.idle()
        self.dialog.check()
        self.idle()
        self.assertIsNotNone(self.dialog.prepared, self.dialog.status.get())
    def reviewed(self):
        self.prepared()
        for value in self.dialog.feature_values.values():
            value.set(True)
        self.dialog._feature_edited()
        self.dialog.preview_features()
        self.idle()
        self.assertIsNotNone(self.dialog.review)

    def test_credentials_clear_before_worker_and_apply_requires_separate_review_and_confirmation(self):
        self.prepared()
        d = self.dialog
        self.assertEqual(d.fields["password"].get(), "")
        self.assertEqual(self.world.credential_references, [{}])
        self.assertEqual(d.feature_checks["terminal"].options["state"], "disabled")
        self.assertNotIn("fixture-ui-secret", d.details.text)
        d.feature_values["terminal"].set(True)
        d._feature_edited()
        self.assertFalse(d.feature_values["commands"].get())
        self.assertFalse(d.feature_values["terminal"].get())
        for value in d.feature_values.values():
            value.set(True)
        d._feature_edited()
        d.preview_features()
        self.idle()
        self.assertNotIn(("apply",), self.world.calls)
        with patch.object(dialog_module.messagebox, "askyesno", create=True, return_value=False):
            d.apply()
        self.assertNotIn(("apply",), self.world.calls)
        with patch.object(dialog_module.messagebox, "askyesno", create=True, return_value=True):
            d.apply()
        self.idle()
        self.assertEqual(self.world.calls.count(("apply",)), 1)
        self.assertEqual(d._features(), {name: True for name in FLAGS})
        d.close()
        self.until(lambda: d.closed)
        self.assertEqual(self.world.calls[-1], ("close",))
        d.on_closed.assert_called_once()

    def test_recovery_and_remaining_temporary_source_are_visible_without_claiming_rollback(self):
        self.world.recovery_required = True
        self.prepared()
        d = self.dialog
        self.assertIn("незавершённая", d.status.get())
        self.assertIn("Найдена незавершённая", d.details.text)
        d.feature_values["commands"].set(True)
        d._feature_edited()
        d.preview_features()
        self.idle()
        self.world.cleanup_required = True
        with patch.object(dialog_module.messagebox, "askyesno", create=True, return_value=True):
            d.apply()
        self.idle()
        self.assertIn("Временный пакет", d.status.get())
        self.assertNotIn("откат", d.status.get())
        self.assertTrue(d.feature_values["commands"].get())

    def test_selection_change_inside_native_confirmation_cannot_apply_previous_server(self):
        self.reviewed()
        d = self.dialog
        def change(*_args, **_kwargs):
            d.selection.set(next(label for label, server in d.servers.items() if server["id"] == OTHER))
            d._context_edited()
            return True
        with patch.object(dialog_module.messagebox, "askyesno", create=True, side_effect=change):
            d.apply()
        self.assertNotIn(("apply",), self.world.calls)
        self.assertIsNone(d.review)

    def test_parent_close_inside_confirmation_prevents_apply(self):
        self.reviewed()
        def close(*_args, **_kwargs):
            self.dialog.close()
            return True
        with patch.object(dialog_module.messagebox, "askyesno", create=True, side_effect=close):
            self.dialog.apply()
        self.until(lambda: self.dialog.closed)
        self.assertNotIn(("apply",), self.world.calls)
        self.dialog.on_closed.assert_called_once()

    def test_cancel_waits_for_worker_and_logout_and_discards_late_success(self):
        self.reviewed()
        self.world.apply_gate, self.world.close_gate = threading.Event(), threading.Event()
        d = self.dialog
        with patch.object(dialog_module.messagebox, "askyesno", create=True, return_value=True):
            d.apply()
        self.assertTrue(self.world.apply_entered.wait(1))
        d.close()
        self.assertFalse(d.closed)
        self.world.controllers[-1].cancel.assert_called_once()
        d.on_closed.assert_not_called()
        self.world.apply_gate.set()
        self.until(lambda: self.world.close_entered.is_set())
        self.assertFalse(d.closed)
        self.assertTrue(d.busy)
        self.assertNotIn("применены и проверены", d.status.get())
        self.world.close_gate.set()
        self.until(lambda: d.closed)
        d.on_closed.assert_called_once()

    def test_read_reply_is_rejected_when_target_context_changed_while_worker_was_pending(self):
        d = self.dialog
        d.load_servers()
        self.idle()
        self.world.prepare_gate = threading.Event()
        d.check()
        self.assertTrue(self.world.prepare_entered.wait(1))
        d.fields["host"].set("different.invalid")
        self.world.prepare_gate.set()
        self.idle()
        self.assertIsNone(d.prepared)
        self.assertEqual(d.apply_button.options["state"], "disabled")

    def test_raw_exceptions_and_replaced_controller_progress_are_not_displayed(self):
        d = self.dialog
        d.load_servers()
        self.idle()
        old = self.world.controllers[-1]
        d.fields["password"].set("another-ui-secret")
        d._auth_edited()
        d.load_servers()
        self.idle()
        before = d.status.get()
        old.progress("late-private-data")
        d.pump()
        self.assertEqual(d.status.get(), before)
        self.world.prepare_error = RuntimeError("raw-private-token")
        d.check()
        self.idle()
        self.assertNotIn("raw-private-token", d.status.get())
        self.assertIsNone(d.prepared)


class LauncherRemoteFeatureGuard(unittest.TestCase):
    def launcher(self):
        if tk is None:
            with patch.dict(sys.modules, {"tkinter": toolkit}):
                from sovagrid_connect.gui import Launcher
        else:
            from sovagrid_connect.gui import Launcher
        launcher = Launcher.__new__(Launcher)
        launcher.remote_features_window = SimpleNamespace(window=SimpleNamespace(lift=Mock()), close=Mock())
        launcher.enrollment_window = launcher.public_web_window = None
        launcher.install_window = launcher.feature_window = launcher.update_window = None
        launcher.tunnel = SimpleNamespace(alive=True, close=Mock())
        launcher.status = Variable()
        launcher.closing = False
        return launcher

    def test_other_management_actions_lift_existing_remote_feature_form(self):
        launcher = self.launcher()
        for method in (launcher.open_enrollment, launcher.open_public_web, launcher.open_install,
                       launcher.open_features, launcher.open_update, launcher.connect):
            method()
        self.assertEqual(launcher.remote_features_window.window.lift.call_count, 6)

    def test_disconnect_and_parent_close_keep_hub_tunnel_until_child_logout(self):
        launcher = self.launcher()
        launcher.disconnect()
        launcher.tunnel.close.assert_not_called()
        launcher.on_close()
        self.assertTrue(launcher.closing)
        launcher.remote_features_window.close.assert_called_once()
        launcher.tunnel.close.assert_not_called()


class RemoteFeatureControllerInterface(unittest.TestCase):
    def test_form_uses_real_controller_session_preview_and_apply_contract(self):
        from sovagrid_connect.remote_agent_features import RemoteAgentFeatures
        from sovagrid_connect.remote_feature_journal import FeatureJournal
        from test_remote_agent_features import Backend, FakeAPI, FakeRPC, ON
        backend = Backend()
        api = FakeAPI(backend)
        dialog = fixture(World())
        with tempfile.TemporaryDirectory() as directory:
            journal = FeatureJournal(Path(directory).resolve() / "features")
            dialog.controller_factory = lambda tunnel, progress: RemoteAgentFeatures(
                tunnel, progress=progress, journal=journal, api_factory=lambda _t: api,
                rpc_factory=lambda *_args, **_kwargs: FakeRPC(backend))
            bundle = {"path": str(Path(directory).resolve() / "approved.tar.gz"), "sha256": "d" * 64}
            def idle():
                deadline = time.monotonic() + 4
                while dialog.busy and time.monotonic() < deadline:
                    dialog.pump()
                    time.sleep(.005)
                dialog.pump()
                self.assertFalse(dialog.busy, dialog.status.get())
            with patch("sovagrid_connect.remote_agent_features.feature_bundle",
                       return_value=(bundle, SimpleNamespace(commits={"sovagrid-agent": "e" * 40}))):
                dialog.load_servers()
                idle()
                dialog.check()
                idle()
                self.assertIsNotNone(dialog.prepared, dialog.status.get())
                self.assertEqual(api.logins, 1, "prepare must reuse the list picker session")
                for value in dialog.feature_values.values():
                    value.set(True)
                dialog._feature_edited()
                dialog.preview_features()
                idle()
                self.assertIsNotNone(dialog.review, dialog.status.get())
                with patch.object(dialog_module.messagebox, "askyesno", create=True, return_value=True):
                    dialog.apply()
                idle()
                self.assertEqual(backend.calls, [("gate", False), ("target", ON), ("gate", True)])
                self.assertEqual(dialog._features(), ON)
                self.assertEqual(journal.list(), [])
                dialog.close()
                deadline = time.monotonic() + 4
                while not dialog.closed and time.monotonic() < deadline:
                    dialog.pump()
                    time.sleep(.005)
                self.assertTrue(dialog.closed)
                self.assertEqual(backend.calls[-1], ("logout",))


GUI_TESTS = tk is not None and os.environ.get("SOVAGRID_GUI_TESTS") == "1"


@unittest.skipUnless(GUI_TESTS, "actual Tk test; run under Xvfb with SOVAGRID_GUI_TESTS=1")
class RemoteFeatureActualTk(unittest.TestCase):
    def test_launcher_small_viewport_keeps_connection_footer_visible_and_settings_scrollable(self):
        from sovagrid_connect.gui import Launcher
        root = tk.Tk()
        self.addCleanup(root.destroy)
        callbacks = []
        root.report_callback_exception = lambda *args: callbacks.append(args)
        with patch("sovagrid_connect.theme.load_preference", return_value="system"):
            launcher = Launcher(root)
        root.update()
        self.assertEqual(tuple(map(bool, root.resizable())), (True, True))
        self.assertLessEqual(root.winfo_height(), max(320, root.winfo_screenheight() - 140))
        root.geometry("800x500")
        root.update()
        canvas = launcher.main_canvas
        self.assertGreater(launcher.main_body.winfo_reqheight(), canvas.winfo_height())

        def footer_visible():
            for widget in (launcher.main_footer, launcher.connect_button,
                           launcher.browser_button, launcher.disconnect_button):
                self.assertTrue(widget.winfo_ismapped())
                self.assertGreaterEqual(widget.winfo_rootx(), root.winfo_rootx())
                self.assertLessEqual(widget.winfo_rootx() + widget.winfo_width(),
                                     root.winfo_rootx() + root.winfo_width())
                self.assertGreaterEqual(widget.winfo_rooty(), root.winfo_rooty())
                self.assertLessEqual(widget.winfo_rooty() + widget.winfo_height(),
                                     root.winfo_rooty() + root.winfo_height())

        footer_visible()
        canvas.yview_moveto(1)
        root.update()
        self.assertGreater(canvas.yview()[0], 0)
        self.assertAlmostEqual(canvas.yview()[1], 1, places=2)
        button = launcher.remote_features_button
        self.assertGreaterEqual(button.winfo_rooty(), canvas.winfo_rooty())
        self.assertLessEqual(button.winfo_rooty() + button.winfo_height(),
                             canvas.winfo_rooty() + canvas.winfo_height())
        footer_visible()
        # Changing between all palettes also updates the exposed canvas edge.
        for selected in ("dark", "light", "system"):
            self.assertTrue(launcher.theme.apply(selected, persist=False))
            root.update()
            self.assertEqual(canvas.cget("background"), root.cget("background"))
            footer_visible()
        self.assertEqual(callbacks, [])

    def test_small_scrolled_form_keeps_actions_visible_and_clears_login_password(self):
        class Theme:
            def style_window(self, _window):
                pass
            def style_text(self, _widget):
                pass
        root = tk.Tk()
        root.geometry("200x100")
        self.addCleanup(root.destroy)
        callbacks = []
        root.report_callback_exception = lambda *args: callbacks.append(args)
        world, closed = World(), []
        dialog = RemoteFeaturesDialog(root, Theme(), SimpleNamespace(options=ConnectionOptions("hub.invalid", user="root")),
            lambda: closed.append(True), controller_factory=world.factory)
        dialog.window.geometry("600x500")
        dialog.fields["password"].set("fixture-ui-secret")
        dialog.fields["host"].set("home.invalid")
        dialog.fields["bundle"].set("/fixture/source.tar.gz")
        def until(predicate):
            deadline = time.monotonic() + 4
            while not predicate() and time.monotonic() < deadline:
                root.update()
                time.sleep(.01)
            root.update()
            self.assertTrue(predicate(), dialog.status.get())
            self.assertEqual(callbacks, [])
        root.update()
        for button in (dialog.check_button, dialog.preview_button, dialog.apply_button, dialog.close_button):
            self.assertTrue(button.winfo_ismapped())
            self.assertGreaterEqual(button.winfo_rootx(), dialog.window.winfo_rootx())
            self.assertLessEqual(button.winfo_rootx() + button.winfo_width(),
                                 dialog.window.winfo_rootx() + dialog.window.winfo_width())
            self.assertGreaterEqual(button.winfo_rooty(), dialog.window.winfo_rooty())
            self.assertLessEqual(button.winfo_rooty() + button.winfo_height(),
                                 dialog.window.winfo_rooty() + dialog.window.winfo_height())
        dialog.load_button.invoke()
        until(lambda: not dialog.busy)
        self.assertEqual(dialog.fields["password"].get(), "")
        self.assertEqual(world.credential_references, [{}])
        dialog.check_button.invoke()
        until(lambda: not dialog.busy)
        self.assertIsNotNone(dialog.prepared)
        self.assertEqual(str(dialog.feature_checks["terminal"].cget("state")), "disabled")
        dialog.feature_checks["commands"].invoke()
        dialog.feature_checks["terminal"].invoke()
        dialog.preview_button.invoke()
        until(lambda: not dialog.busy)
        self.assertIsNotNone(dialog.review)
        self.assertNotIn(("apply",), world.calls)
        dialog.close()
        until(lambda: dialog.closed)
        self.assertEqual(closed, [True])


if __name__ == "__main__":
    unittest.main()
