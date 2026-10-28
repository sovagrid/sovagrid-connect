# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Generation stays off the Tk thread and public copy cannot copy a secret."""

from pathlib import Path
import queue
import tempfile
import threading
import time
import types
import sys
import unittest
from unittest import mock

from sovagrid_connect.keygen import GeneratedKey

# Controller checks do not need a display or a Python build linked to Tk.
# Actual widget construction remains part of the packaged GUI/manual smoke.
try:
    import tkinter
except ImportError:
    toolkit = types.ModuleType("tkinter")
    toolkit.filedialog, toolkit.messagebox, toolkit.ttk = (types.ModuleType(name) for name in
                                                         ("filedialog", "messagebox", "ttk"))
    with mock.patch.dict(sys.modules, {"tkinter": toolkit}):
        from sovagrid_connect.gui import Launcher
        from sovagrid_connect.keygen_dialog import KeyGenerationDialog
else:
    from sovagrid_connect.gui import Launcher
    from sovagrid_connect.keygen_dialog import KeyGenerationDialog


class Variable:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class Control:
    def __init__(self):
        self.options = {}
        self.text = ""
        self.destroyed = False

    def configure(self, **options):
        self.options.update(options)

    def after(self, *_args):
        pass

    def delete(self, *_args):
        self.text = ""

    def insert(self, _index, text):
        self.text = text

    def destroy(self):
        self.destroyed = True


class Root(Control):
    def clipboard_clear(self):
        self.text = ""

    def clipboard_append(self, value):
        self.text += value


def dialog():
    instance = KeyGenerationDialog.__new__(KeyGenerationDialog)
    instance.root, instance.window = Root(), Control()
    instance.target = "jump_identity"
    instance.busy = instance.close_requested = instance.closed = False
    instance.generator = instance.result = None
    instance.events = queue.SimpleQueue()
    instance.path, instance.encrypted = Variable("/chosen/key"), Variable(True)
    instance.status, instance.fingerprint = Variable(), Variable()
    for name in ("path_entry", "choose_button", "protect_check", "create_button", "close_button", "public_text", "copy_button"):
        setattr(instance, name, Control())
    instance.created = []
    instance.on_created = lambda target, result: instance.created.append((target, result))
    instance.on_closed = mock.Mock()
    return instance


class KeyGenerationDialogTests(unittest.TestCase):
    def test_slow_generation_returns_control_and_freezes_the_bound_target_and_destination(self):
        instance = dialog()
        release, started = threading.Event(), threading.Event()
        captured = {}

        class Generator:
            def generate(self, path, *, encrypted):
                captured.update(path=path, encrypted=encrypted)
                started.set()
                if not release.wait(3):
                    raise RuntimeError()
                return GeneratedKey(path, Path(str(path) + ".pub"), "ssh-ed25519 public-fixture", "SHA256:fixture", encrypted)

        with mock.patch("sovagrid_connect.keygen_dialog.KeyGenerator", Generator):
            start = time.monotonic()
            instance.begin()
            self.assertLess(time.monotonic() - start, 0.25)
            self.assertTrue(started.wait(2))
            self.assertTrue(instance.busy)
            self.assertEqual(instance.path_entry.options["state"], "disabled")
            instance.path.set("/different/new-value")
            release.set()
            deadline = time.monotonic() + 3
            while instance.events.empty() and time.monotonic() < deadline:
                time.sleep(0.01)
            instance.pump()
        self.assertEqual(captured, {"path": Path("/chosen/key"), "encrypted": True})
        self.assertEqual(instance.created[0][0], "jump_identity")
        self.assertEqual(instance.created[0][1].private_path, Path("/chosen/key"))
        self.assertEqual(instance.public_text.text, "ssh-ed25519 public-fixture")
        instance.copy_public()
        self.assertEqual(instance.root.text, "ssh-ed25519 public-fixture")
        self.assertNotIn("/chosen/key", instance.root.text)

    def test_close_cancels_worker_without_destroying_the_window_until_cleanup_finishes(self):
        instance = dialog()
        instance.generator = mock.Mock()
        generator = instance.generator
        instance.busy = True
        instance.close()
        generator.cancel.assert_called_once()
        self.assertTrue(instance.close_requested)
        self.assertFalse(instance.window.destroyed)
        instance.events.put((generator, "Создание ключа отменено."))
        instance.pump()
        self.assertTrue(instance.window.destroyed)
        instance.on_closed.assert_called_once()
        self.assertFalse(instance.created)

    def test_old_worker_cannot_fill_a_new_generation_window(self):
        instance = dialog()
        instance.generator = object()
        instance.busy = True
        old = object()
        instance.events.put((old, GeneratedKey(Path("old"), Path("old.pub"), "old public", "old fingerprint", False)))
        instance.pump()
        self.assertFalse(instance.created)
        self.assertEqual(instance.public_text.text, "")
        self.assertTrue(instance.busy)

    def test_cancel_after_publication_before_ui_delivery_keeps_completed_key_visible(self):
        instance = dialog()
        instance.generator = mock.Mock()
        generator = instance.generator
        instance.busy = True
        instance.close()
        result = GeneratedKey(Path("saved-private"), Path("saved-private.pub"), "ssh-ed25519 public", "SHA256:fixture", True)
        instance.events.put((generator, result))
        instance.pump()
        self.assertFalse(instance.window.destroyed)
        self.assertFalse(instance.close_requested)
        self.assertEqual(instance.result, result)
        self.assertEqual(instance.created, [("jump_identity", result)])
        self.assertIn("успел сохраниться", instance.status.get())
        instance.copy_public()
        self.assertEqual(instance.root.text, result.public_key)

    def test_launcher_selects_only_the_intended_private_path_and_never_private_bytes(self):
        launcher = Launcher.__new__(Launcher)
        launcher.values = {"identity": Variable("target-original"), "jump_identity": Variable("jump-original")}
        launcher.status = Variable()
        launcher.key_window = None
        launcher.closing = False
        result = GeneratedKey(Path("new-jump"), Path("new-jump.pub"), "ssh-ed25519 public", "SHA256:fixture", True)
        launcher.key_created("jump_identity", result)
        self.assertEqual(launcher.values["identity"].get(), "target-original")
        self.assertEqual(launcher.values["jump_identity"].get(), "new-jump")
        self.assertNotIn(result.public_key, launcher.status.get())

    def test_completed_export_cancels_pending_app_exit_so_public_key_can_be_seen(self):
        launcher = Launcher.__new__(Launcher)
        launcher.values = {"identity": Variable("target"), "jump_identity": Variable("jump")}
        launcher.status = Variable()
        launcher.key_window = mock.Mock(close_requested=True)
        launcher.closing = True
        result = GeneratedKey(Path("saved-private"), Path("saved-private.pub"), "ssh-ed25519 public", "SHA256:fixture", True)
        launcher.key_created("identity", result)
        self.assertFalse(launcher.closing)
        self.assertIn("успел сохраниться", launcher.status.get())
        self.assertEqual(launcher.values["identity"].get(), "saved-private")


if __name__ == "__main__":
    unittest.main()
