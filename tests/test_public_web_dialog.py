# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""HTTPS UI does not confuse saved state, a preview and verified TLS success."""
import copy
import os
import queue
import sys
import threading
import time
import types
import unittest
from unittest import mock

from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.public_web import PublicWebError, public_panel_url, public_url
from test_public_web import CONFIG, SOURCE, STATE

try:
    import tkinter as tk
except ImportError:
    tk = None
    toolkit = types.ModuleType("tkinter")
    toolkit.messagebox, toolkit.ttk = (types.ModuleType(name) for name in ("messagebox", "ttk"))
    with mock.patch.dict(sys.modules, {"tkinter": toolkit}):
        from sovagrid_connect import public_web_dialog as dialog_module
else:
    from sovagrid_connect import public_web_dialog as dialog_module

PublicWebDialog = dialog_module.PublicWebDialog


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

    def delete(self, *_args):
        assert threading.current_thread() is threading.main_thread()
        self.text = ""

    def insert(self, _index, text):
        assert threading.current_thread() is threading.main_thread()
        self.text = text

    def grab_release(self):
        assert threading.current_thread() is threading.main_thread()

    def destroy(self):
        assert threading.current_thread() is threading.main_thread()
        self.destroyed = True


class World:
    def __init__(self):
        self.state = {"protocol": 1, "ok": True, "enabled": True, "config": CONFIG, "expected_state_sha256": STATE}
        self.rpcs = []
        self.calls = []
        self.apply_error = None
        self.allow_late_success = False

    def factory(self, _options, *, progress):
        world = self
        class RPC:
            def __init__(self):
                self.progress = progress
                self.cancel = mock.Mock()
                self.apply_entered, self.release_apply = threading.Event(), threading.Event()
                self.release_apply.set()

            def status(self):
                world.calls.append(("status",))
                return copy.deepcopy(world.state)

            def preview(self, config):
                world.calls.append(("preview", copy.deepcopy(config)))
                self.progress("Проверяем адрес")
                return {"protocol": 1, "ok": True, "config": copy.deepcopy(config),
                    "expected_state_sha256": world.state["expected_state_sha256"],
                    "source_manifest_sha256": SOURCE, "changed": True, "url": public_url(config),
                    "certificate_verified": False}

            def apply(self, config, **pins):
                world.calls.append(("apply", copy.deepcopy(config), pins))
                self.progress("Ждём подтверждения сертификата")
                self.apply_entered.set()
                if not self.release_apply.wait(3):
                    raise RuntimeError("Test worker was not released")
                if world.apply_error:
                    raise world.apply_error
                if self.cancel.called and not world.allow_late_success:
                    raise PublicWebError("CANCELLED")
                return {"protocol": 1, "ok": True, "enabled": True, "config": copy.deepcopy(config),
                    "expected_state_sha256": "c" * 64, "source_manifest_sha256": SOURCE,
                    "changed": True, "url": public_url(config), "certificate_verified": True}

            def disable(self, **pins):
                world.calls.append(("disable", pins))
                return {"protocol": 1, "ok": True, "enabled": False, "expected_state_sha256": None, "changed": True}

        rpc = RPC()
        self.rpcs.append(rpc)
        return rpc


def dialog(world):
    d = PublicWebDialog.__new__(PublicWebDialog)
    d.options = ConnectionOptions("hub.invalid", user="fixture")
    d.rpc_factory = world.factory
    d.rpc = d.progress_binding = d.current = d.preview = d.confirmed_url = None
    d.generation = 0
    d.busy = d.closed = d.close_requested = False
    d.events = queue.SimpleQueue()
    d.address = Variable(CONFIG["address"])
    d.panel_path = Variable(CONFIG["panel_path"])
    d.root_behavior = Variable(dialog_module.ROOT_LABELS[CONFIG["root_behavior"]])
    d.status, d.state_label = Variable(), Variable()
    d.window, d.details = Control(), Control()
    for name in ("address_entry", "path_entry", "root_select", "check_button", "apply_button", "disable_button", "open_button", "close_button"):
        setattr(d, name, Control())
    d.on_closed = mock.Mock()
    return d


def until(d, predicate, update=None):
    deadline = time.monotonic() + 3
    while not predicate() and time.monotonic() < deadline:
        (update or d.pump)()
        time.sleep(.005)
    (update or d.pump)()
    if not predicate():
        raise AssertionError("HTTPS UI worker did not finish: " + d.status.get())


class PublicWebDialogTests(unittest.TestCase):
    def test_saved_staging_is_labelled_unverified_and_can_be_disabled_or_previewed_as_production(self):
        for action in ("disable", "check"):
            with self.subTest(action=action):
                world = World()
                world.state["config"] = {**CONFIG, "acme_environment": "staging"}
                d = dialog(world)
                d.refresh()
                until(d, lambda: not d.busy)
                self.assertIn("Тестовый сертификат, доступность не подтверждена", d.state_label.get())
                self.assertIsNone(d.confirmed_url)
                self.assertEqual(d.open_button.options["state"], "disabled")
                if action == "disable":
                    with mock.patch.object(dialog_module.messagebox, "askyesno", return_value=True, create=True):
                        d.disable()
                    until(d, lambda: not d.busy)
                    self.assertFalse(d.current["enabled"])
                    self.assertEqual(world.calls[-1], ("disable", {"expected_state_sha256": STATE}))
                else:
                    d.check()
                    until(d, lambda: not d.busy)
                    self.assertEqual(world.calls[-1], ("preview", CONFIG))
                    self.assertEqual(d.preview["config"]["acme_environment"], "production")
                    self.assertIsNone(d.confirmed_url)

    def test_status_prefills_existing_address_but_check_keeps_the_new_desired_address(self):
        world = World()
        d = dialog(world)
        d.address.set("8.8.8.8")
        d.refresh()
        until(d, lambda: not d.busy)
        self.assertEqual(d.address.get(), CONFIG["address"])
        d.address.set("new.sovagrid.org")
        d.check()
        until(d, lambda: not d.busy)
        self.assertEqual(d.address.get(), "new.sovagrid.org")
        self.assertEqual(d.preview["config"]["address"], "new.sovagrid.org")
        self.assertEqual(d.current["config"]["address"], CONFIG["address"])

    def test_admin_can_review_custom_panel_path_and_root_behavior(self):
        world = World()
        d = dialog(world)
        d.panel_path.set("/ops/monitoring/")
        d.root_behavior.set(dialog_module.ROOT_LABELS["redirect"])
        d.check()
        until(d, lambda: not d.busy)
        self.assertEqual(d.preview["config"]["panel_path"], "/ops/monitoring/")
        self.assertEqual(d.preview["config"]["root_behavior"], "redirect")
        self.assertIn("https://panel.sovagrid.org/ops/monitoring/", d.details.text)
        with mock.patch.object(dialog_module.messagebox, "askyesno", return_value=True, create=True):
            d.apply()
        until(d, lambda: not d.busy)
        self.assertEqual(d.confirmed_url, "https://panel.sovagrid.org/ops/monitoring/")

    def test_saved_state_and_preview_are_not_verified_success_then_explicit_apply_uses_reviewed_pins(self):
        world = World()
        d = dialog(world)
        d.refresh()
        until(d, lambda: not d.busy)
        self.assertIn("Настроен адрес", d.state_label.get())
        self.assertIn("ещё не проверены", d.state_label.get())
        self.assertIsNone(d.confirmed_url)
        self.assertEqual(d.open_button.options["state"], "disabled")
        old_rpc = d.rpc
        d.check()
        until(d, lambda: not d.busy)
        self.assertIn("Сертификат пока не проверен", d.details.text)
        self.assertEqual(d.apply_button.options["state"], "normal")
        self.assertNotIn("apply", [call[0] for call in world.calls])
        rpc = d.rpc
        rpc.release_apply.clear()
        self.addCleanup(rpc.release_apply.set)
        with mock.patch.object(dialog_module.messagebox, "askyesno", return_value=True, create=True):
            d.apply()
        self.assertTrue(rpc.apply_entered.wait(1))
        old_rpc.progress("Stale status from previous RPC")
        d.pump()
        self.assertTrue(d.busy)
        self.assertEqual(d.status.get(), "Ждём подтверждения сертификата")
        self.assertIsNone(d.current)
        self.assertIsNone(d.confirmed_url)
        d.address.set("changed.sovagrid.org")
        rpc.release_apply.set()
        until(d, lambda: not d.busy)
        self.assertEqual(world.calls[-1], ("apply", CONFIG, {
            "expected_state_sha256": STATE, "source_manifest_sha256": SOURCE}))
        self.assertEqual(d.confirmed_url, public_panel_url(CONFIG))
        self.assertIn("HTTPS проверен", d.state_label.get())
        with mock.patch.object(dialog_module.webbrowser, "open") as open_site:
            d.open_site()
            open_site.assert_called_once_with(public_panel_url(CONFIG))

    def test_modal_close_or_new_preview_cannot_apply_or_disable_a_stale_confirmation(self):
        for action in ("apply", "disable"):
            for mutation in ("close", "refresh"):
                with self.subTest(action=action, mutation=mutation):
                    world = World()
                    d = dialog(world)
                    d.check()
                    until(d, lambda: not d.busy)
                    def confirm(*_args, **_kwargs):
                        (d.close if mutation == "close" else d.refresh)()
                        return True
                    with mock.patch.object(dialog_module.messagebox, "askyesno", side_effect=confirm, create=True):
                        getattr(d, action)()
                    self.assertNotIn(action, [call[0] for call in world.calls])
                    if not d.closed:
                        until(d, lambda: not d.busy)
                        d.close()
                    d.on_closed.assert_called_once()

    def test_cancel_waits_for_worker_and_ignores_late_success_without_claiming_certificate_verified(self):
        world = World()
        world.allow_late_success = True
        d = dialog(world)
        d.check()
        until(d, lambda: not d.busy)
        rpc = d.rpc
        rpc.release_apply.clear()
        self.addCleanup(rpc.release_apply.set)
        with mock.patch.object(dialog_module.messagebox, "askyesno", return_value=True, create=True):
            d.apply()
        self.assertTrue(rpc.apply_entered.wait(1))
        d.close()
        self.assertFalse(d.closed)
        self.assertFalse(d.window.destroyed)
        rpc.cancel.assert_called_once()
        self.assertIsNone(d.preview)
        rpc.release_apply.set()
        until(d, lambda: d.closed)
        self.assertIsNone(d.confirmed_url)
        self.assertNotIn("HTTPS проверен", d.state_label.get())
        d.on_closed.assert_called_once()

    def test_failed_mutation_requires_fresh_state_and_never_renders_unexpected_exception_details(self):
        for error in (PublicWebError("PUBLIC_UNHEALTHY"), RuntimeError("private-remote-output-canary")):
            with self.subTest(error=type(error).__name__):
                world = World()
                world.apply_error = error
                d = dialog(world)
                d.check()
                until(d, lambda: not d.busy)
                with mock.patch.object(dialog_module.messagebox, "askyesno", return_value=True, create=True):
                    d.apply()
                until(d, lambda: not d.busy)
                self.assertIsNone(d.current)
                self.assertIsNone(d.preview)
                self.assertIsNone(d.confirmed_url)
                self.assertEqual(d.disable_button.options["state"], "disabled")
                self.assertEqual(d.apply_button.options["state"], "disabled")
                self.assertNotIn("private-remote-output-canary", d.status.get())
                d.refresh()
                until(d, lambda: not d.busy)
                self.assertIn("Настроен адрес", d.state_label.get())
                self.assertIsNone(d.confirmed_url)


@unittest.skipUnless(os.environ.get("SOVAGRID_GUI_TESTS") == "1", "Real Tk UI; opt in under Xvfb")
class PublicWebWidgetTests(unittest.TestCase):
    def test_small_window_keeps_actions_visible_and_explicit_review_precedes_apply(self):
        root = tk.Tk()
        self.addCleanup(root.destroy)
        # An X11 transient follows its parent's visibility. Keep the parent
        # mapped so this test measures the real dialog rather than a hidden one.
        root.geometry("200x100")
        root.update()
        callbacks = []
        root.report_callback_exception = lambda *args: callbacks.append(args)
        world = World()
        theme = types.SimpleNamespace(style_window=lambda _window: None, style_text=lambda _text: None)
        d = PublicWebDialog(root, theme, ConnectionOptions(CONFIG["address"], user="fixture"),
                            mock.Mock(), rpc_factory=world.factory)
        self.addCleanup(lambda: d.close() if not d.closed else None)
        d.window.geometry("540x500")
        until(d, lambda: d.rpc is not None and not d.busy, root.update)
        for button in (d.check_button, d.apply_button, d.disable_button, d.open_button, d.close_button):
            self.assertTrue(button.winfo_ismapped())
            self.assertGreaterEqual(button.winfo_rooty(), d.window.winfo_rooty())
            self.assertLessEqual(button.winfo_rooty() + button.winfo_height(),
                                 d.window.winfo_rooty() + d.window.winfo_height())
        d.check_button.invoke()
        until(d, lambda: not d.busy, root.update)
        self.assertNotIn("apply", [call[0] for call in world.calls])
        with mock.patch.object(dialog_module.messagebox, "askyesno", return_value=True):
            d.apply_button.invoke()
        until(d, lambda: not d.busy, root.update)
        self.assertIn("HTTPS проверен", d.state_label.get())
        pending = d._pump_after
        d.close()
        self.assertTrue(d.closed)
        self.assertNotIn(pending, root.tk.call("after", "info"))
        root.update()
        self.assertEqual(callbacks, [])


if __name__ == "__main__":
    unittest.main()
