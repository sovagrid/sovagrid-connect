# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The update wizard must not silently select an old adjacent archive."""

from __future__ import annotations

import queue
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.server_bundle_download import PUBLISHED_SERVER_SOURCE_SHA256

try:
    from sovagrid_connect.gui import Launcher
except ImportError:  # Headless Python builds need not include Tkinter.
    Launcher = None


class Variable:
    def __init__(self, value=None):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


@unittest.skipIf(Launcher is None, "Tkinter unavailable")
class GuiUpdateSourceTests(unittest.TestCase):
    def _open(self, nearby):
        launcher = Launcher.__new__(Launcher)
        launcher.root = Mock()
        launcher.theme = Mock()
        launcher.events = queue.SimpleQueue()
        launcher.closing = False
        launcher.installing = False
        launcher.connecting = False
        launcher.install_window = launcher.feature_window = launcher.update_window = None
        launcher.update_start_button = launcher.update_apply_button = None
        launcher.update_auto_button = launcher.update_server_auto_button = None
        launcher.update_server_status_button = launcher.update_server_disarm_button = None
        launcher.update_preview = launcher.update_prepared = launcher.update_source_path = None
        launcher.update_source_controls = []
        launcher._lift_management_window = Mock(return_value=False)
        launcher._options = lambda: ConnectionOptions("server.example", "root")
        for name in ("install_button", "feature_button", "update_button", "connect_button"):
            setattr(launcher, name, Mock())
        controls = {}
        modes = []
        manager = Mock()
        manager.preview_update.return_value = SimpleNamespace(sha256=PUBLISHED_SERVER_SOURCE_SHA256)

        def button(*_args, **kwargs):
            controls[kwargs.get("text")] = kwargs.get("command")
            return Mock()

        def radio(*_args, **kwargs):
            modes.append(kwargs["variable"])
            controls[kwargs.get("text")] = kwargs.get("command")
            return Mock()

        patches = (
            patch("sovagrid_connect.gui.nearby_server_bundle", return_value=nearby),
            patch("sovagrid_connect.gui.tk.Toplevel", return_value=Mock()),
            patch("sovagrid_connect.gui.tk.StringVar", Variable),
            patch("sovagrid_connect.gui.ttk.Frame", return_value=Mock()),
            patch("sovagrid_connect.gui.ttk.Label", return_value=Mock()),
            patch("sovagrid_connect.gui.ttk.LabelFrame", return_value=Mock()),
            patch("sovagrid_connect.gui.ttk.Entry", return_value=Mock()),
            patch("sovagrid_connect.gui.ttk.Radiobutton", side_effect=radio),
            patch("sovagrid_connect.gui.ttk.Button", side_effect=button),
            patch("sovagrid_connect.gui.ServerInstaller", return_value=manager),
            patch("sovagrid_connect.gui.threading.Thread",
                  side_effect=lambda target, daemon: SimpleNamespace(start=target)),
        )
        for active in patches:
            active.start()
            self.addCleanup(active.stop)
        launcher.open_update()
        return launcher, controls, modes, manager

    def test_stale_nearby_archive_defaults_to_pinned_release(self) -> None:
        pinned = Path("/tmp/published-source.tar.gz")
        launcher, controls, modes, manager = self._open((Path("/tmp/old-source.tar.gz"), "a" * 64))
        self.assertEqual(modes[0].get(), "release")
        with patch("sovagrid_connect.gui.cached_published_server_bundle", return_value=pinned) as download:
            controls["Проверить пакет и сервер"]()
        download.assert_called_once()
        manager.preview_update.assert_called_once_with(
            pinned, expected_sha256=PUBLISHED_SERVER_SOURCE_SHA256)
        self.assertEqual(launcher.events.get()[0], "update_preview")

    def test_stale_nearby_archive_requires_explicit_custom_selection(self) -> None:
        _launcher, controls, modes, manager = self._open((Path("/tmp/old-source.tar.gz"), "a" * 64))
        modes[0].set("local")
        controls["Свой архив"]()
        with patch("sovagrid_connect.gui.messagebox.showerror") as error:
            controls["Проверить пакет и сервер"]()
        error.assert_called_once()
        manager.preview_update.assert_not_called()

    def test_exact_nearby_archive_is_selected_and_pinned(self) -> None:
        local = Path("/tmp/exact-source.tar.gz")
        _launcher, controls, modes, manager = self._open((local, PUBLISHED_SERVER_SOURCE_SHA256))
        self.assertEqual(modes[0].get(), "local")
        controls["Проверить пакет и сервер"]()
        manager.preview_update.assert_called_once_with(
            local, expected_sha256=PUBLISHED_SERVER_SOURCE_SHA256)

    def test_explicit_custom_archive_remains_available(self) -> None:
        local = Path("/tmp/my-source.tar.gz")
        _launcher, controls, modes, manager = self._open(None)
        with patch("sovagrid_connect.gui.filedialog.askopenfilename", return_value=str(local)):
            controls["Выбрать свой архив…"]()
        self.assertEqual(modes[0].get(), "local")
        controls["Проверить пакет и сервер"]()
        manager.preview_update.assert_called_once_with(local, expected_sha256=None)


if __name__ == "__main__":
    unittest.main()
