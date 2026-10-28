# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""An unattended transaction must hold the GUI's management and exit guard."""

from __future__ import annotations

from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sovagrid_connect.core import ConnectionOptions

try:
    from sovagrid_connect.gui import Launcher
except ImportError:  # Headless Python builds need not include Tkinter.
    Launcher = None


@unittest.skipIf(Launcher is None, "Tkinter unavailable")
class GuiAutoUpdateTests(unittest.TestCase):
    def launcher(self):
        launcher = Launcher.__new__(Launcher)
        launcher.closing = launcher._auto_update_inflight = launcher.installing = launcher.connecting = False
        launcher._auto_last_check = 0.0
        launcher.install_window = launcher.feature_window = launcher.update_window = None
        launcher.enrollment_window = launcher.public_web_window = None
        launcher.remote_features_window = launcher.key_window = None
        launcher.tunnel = None
        launcher.root = Mock()
        launcher.status = Mock()
        launcher.install_button = launcher.feature_button = Mock()
        launcher.update_button = launcher.connect_button = Mock()
        launcher.update_start_button = None
        launcher._options = lambda: ConnectionOptions("server.example", "root")
        launcher._auto_policy_store = lambda: SimpleNamespace(load=lambda _key: SimpleNamespace(due=lambda _now: True))
        return launcher

    def test_auto_apply_blocks_conflicting_actions_and_exit_until_result(self):
        launcher = self.launcher()
        with patch("sovagrid_connect.gui.time.monotonic", return_value=1000.0), \
             patch("sovagrid_connect.gui.ServerInstaller", return_value=Mock()), \
             patch("sovagrid_connect.gui.threading.Thread") as thread:
            launcher._auto_update_check()
        thread.assert_called_once()
        thread.return_value.start.assert_called_once()
        self.assertTrue(launcher._auto_update_inflight)
        self.assertTrue(launcher.installing)
        for button in (launcher.install_button, launcher.feature_button,
                       launcher.update_button, launcher.connect_button):
            button.configure.assert_called_with(state="disabled")
        with patch("sovagrid_connect.gui.messagebox.showinfo") as notice:
            launcher.on_close()
        notice.assert_called_once()
        launcher.root.destroy.assert_not_called()
        launcher._auto_update_inflight = False
        launcher._end_update_work()
        self.assertFalse(launcher.installing)

    def test_open_management_form_defers_auto_apply(self):
        launcher = self.launcher()
        launcher.enrollment_window = object()
        launcher._options = Mock(side_effect=AssertionError("must not choose a target"))
        launcher._auto_update_check()
        launcher._options.assert_not_called()
        self.assertFalse(launcher._auto_update_inflight)

    def test_server_timer_arm_button_requires_prepared_exact_digest(self):
        launcher = self.launcher()
        launcher.update_window = object()
        launcher.update_apply_button = Mock()
        launcher.update_auto_button = Mock()
        launcher.update_server_auto_button = Mock()
        launcher.update_server_status_button = Mock()
        launcher.update_server_disarm_button = Mock()
        launcher.update_preview = SimpleNamespace(sha256="a" * 64)
        launcher.update_prepared = SimpleNamespace(sha256="b" * 64)
        launcher._restore_update_dialog_controls()
        launcher.update_server_auto_button.configure.assert_called_with(state="disabled")
        launcher.update_server_status_button.configure.assert_called_with(state="normal")
        launcher.update_prepared = SimpleNamespace(sha256="a" * 64)
        launcher._restore_update_dialog_controls()
        launcher.update_server_auto_button.configure.assert_called_with(state="normal")


if __name__ == "__main__":
    unittest.main()
